/*
 * Transaction routines for test server.
 *
 * Copyright (C) 2014-2015 SUSE
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h> /* for htons */

#include <pwd.h>
#include <grp.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <termios.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <ctype.h>
#include <limits.h>

#include "server.h"


struct transaction_channel {
	struct transaction_channel *next;

	unsigned char		id;		/* corresponds to a packet type (eg '0' or 'd') */
	bool			sync;		/* if true, all writes are fully synchronous */

	twopence_sock_t *	socket;

	struct {
	    void		(*read_eof)(transaction_t *, transaction_channel_t *);
	} callbacks;
};

/*
 * Transaction channel primitives
 */
static transaction_channel_t *
transaction_channel_from_fd(int fd, int flags)
{
	transaction_channel_t *sink;
	twopence_sock_t *sock;

	sock = twopence_sock_new_flags(fd, flags);

	sink = calloc(1, sizeof(*sink));
	sink->socket = sock;

	return sink;
}

static void
transaction_channel_free(transaction_channel_t *sink)
{
	twopence_debug("%s(%c)", __func__, sink->id);
	if (sink->socket)
		twopence_sock_free(sink->socket);
	sink->socket = NULL;
	free(sink);
}

bool
transaction_channel_is_read_eof(const transaction_channel_t *channel)
{
	twopence_sock_t *sock = channel->socket;

	if (sock)
		return twopence_sock_is_read_eof(sock);
	return false;
}

void
transaction_channel_set_callback_read_eof(transaction_channel_t *channel, void (*fn)(transaction_t *, transaction_channel_t *))
{
	channel->callbacks.read_eof = fn;
}

static void
transaction_channel_list_purge(transaction_channel_t **list)
{
	transaction_channel_t *channel;

	while ((channel = *list) != NULL) {
		if (channel->socket && twopence_sock_is_dead(channel->socket)) {
			*list = channel->next;
			transaction_channel_free(channel);
		} else {
			list = &channel->next;
		}
	}
}

static void
transaction_channel_list_close(transaction_channel_t **list, unsigned char id)
{
	transaction_channel_t *channel;

	while ((channel = *list) != NULL) {
		if (id == 0 || channel->id == id) {
			*list = channel->next;
			transaction_channel_free(channel);
		} else {
			list = &channel->next;
		}
	}
}

/*
 * Command handling
 */
transaction_t *
transaction_new(twopence_sock_t *client, unsigned int type, const twopence_protocol_state_t *ps)
{
	transaction_t *trans;

	twopence_debug("%s('%c', %u)\n", __func__, type, ps->xid);
	trans = calloc(1, sizeof(*trans));
	trans->ps = *ps;
	trans->id = ps->xid;
	trans->type = type;
	trans->client_sock = client;
	return trans;
}

void
transaction_free(transaction_t *trans)
{
	/* Do not free trans->client_sock, we don't own it */

	transaction_channel_list_close(&trans->local_sink, 0);
	transaction_channel_list_close(&trans->local_source, 0);

	memset(trans, 0, sizeof(*trans));
	free(trans);
}

unsigned int
transaction_num_channels(const transaction_t *trans)
{
	transaction_channel_t *channel;
	unsigned int count = 0;

	for (channel = trans->local_sink; channel; channel = channel->next)
		count++;
	for (channel = trans->local_source; channel; channel = channel->next)
		count++;
	return count;
}

transaction_channel_t *
transaction_attach_local_sink(transaction_t *trans, int fd, unsigned char id)
{
	transaction_channel_t *sink;

	/* Make I/O to this file descriptor non-blocking */
	fcntl(fd, F_SETFL, O_NONBLOCK);

	sink = transaction_channel_from_fd(fd, O_WRONLY);
	sink->id = id;

	sink->next = trans->local_sink;
	trans->local_sink = sink;
	return sink;
}

void
transaction_close_sink(transaction_t *trans, unsigned char id)
{
	twopence_debug("%s(%c)\n", __func__, id);
	transaction_channel_list_close(&trans->local_sink, id);
}

transaction_channel_t *
transaction_attach_local_source(transaction_t *trans, int fd, unsigned char channel_id)
{
	transaction_channel_t *source;

	/* Make I/O to this file descriptor non-blocking */
	fcntl(fd, F_SETFL, O_NONBLOCK);

	source = transaction_channel_from_fd(fd, O_RDONLY);
	source->id = channel_id;

	source->next = trans->local_source;
	trans->local_source = source;
	return source;
}

void
transaction_close_source(transaction_t *trans, unsigned char id)
{
	twopence_debug("%s(%c)\n", __func__, id);
	transaction_channel_list_close(&trans->local_source, id);
}

/*
 * Write data to the sink.
 * Note that the buffer is a temporary one on the stack, so if we
 * want to enqueue it to the socket, it has to be cloned first.
 * This is taken care of by twopence_sock_xmit_shared()
 */
static bool
transaction_channel_write_data(transaction_channel_t *sink, twopence_buf_t *payload)
{
	twopence_sock_t *sock;

	/* If there's no socket attached, silently discard the data */
	if ((sock = sink->socket) == NULL)
		return true;

	twopence_debug("About to write %u bytes of data to local sink\n", twopence_buf_count(payload));
	if (twopence_sock_xmit_shared(sock, payload) < 0)
		return false;

	return true;
}

static void
transaction_channel_write_eof(transaction_channel_t *sink)
{
	twopence_sock_t *sock = sink->socket;

	if (sock)
		twopence_sock_shutdown_write(sock);
}

int
transaction_channel_poll(transaction_channel_t *sink, struct pollfd *pfd)
{
	twopence_sock_t *sock = sink->socket;

	if (sock && !twopence_sock_is_dead(sock)) {
		twopence_buf_t *bp;

		twopence_sock_prepare_poll(sock);

		/* If needed, post a new receive buffer to the socket.
		 * Note: this is a NOP for sink channels, as their socket
		 * already has read_eof set, so that a recvbuf is never
		 * posted to it.
		 */
		if (!twopence_sock_is_read_eof(sock) && (bp = twopence_sock_get_recvbuf(sock)) == NULL) {
			/* When we receive data from a command's output stream, or from
			 * a file that is being extracted, we do not want to copy
			 * the entire packet - instead, we reserve some room for the
			 * protocol header, which we just tack on once we have the data.
			 */
			bp = twopence_buf_new(TWOPENCE_PROTO_MAX_PACKET);
			twopence_buf_reserve_head(bp, TWOPENCE_PROTO_HEADER_SIZE);

			twopence_sock_post_recvbuf(sock, bp);
		}

		if (twopence_sock_fill_poll(sock, pfd))
			return 1;
	}

	return 0;
}

static void
transaction_channel_doio(transaction_t *trans, transaction_channel_t *channel)
{
	twopence_sock_t *sock = channel->socket;

	if (sock) {
		twopence_buf_t *bp;

		if (twopence_sock_doio(sock) < 0) {
			transaction_fail(trans, errno);
			twopence_sock_mark_dead(sock);
			return;
		}

		/* Only source channels will even have a recv buffer posted
		 * to them. If that is non-empty, queue it to the transport
		 * socket. */
		if ((bp = twopence_sock_take_recvbuf(sock)) != NULL) {
			twopence_protocol_push_header_ps(bp, &trans->ps, channel->id);
			twopence_sock_queue_xmit(trans->client_sock, bp);
		}

		/* For file extractions, we want to send an EOF packet
		 * when the file has been transmitted in its entirety.
		 */
		if (twopence_sock_is_read_eof(sock) && channel->callbacks.read_eof) {
			channel->callbacks.read_eof(trans, channel);
			channel->callbacks.read_eof = NULL;
		}
	}
}

int
transaction_fill_poll(transaction_t *trans, struct pollfd *pfd, unsigned int max)
{
	unsigned int nfds = 0;

	if (trans->local_sink != NULL) {
		transaction_channel_t *sink;

		for (sink = trans->local_sink; sink; sink = sink->next) {
			if (nfds < max && transaction_channel_poll(sink, pfd + nfds))
				nfds++;
		}
	}

	/* If the client socket's write queue is already bursting with data,
	 * refrain from queuing more until some of it has been drained */
	if (twopence_sock_xmit_queue_allowed(trans->client_sock)) {
		transaction_channel_t *source;

		for (source = trans->local_source; source; source = source->next) {
			if (nfds < max && transaction_channel_poll(source, pfd + nfds))
				nfds++;
		}
	}

	return nfds;
}

void
transaction_doio(transaction_t *trans)
{
	transaction_channel_t *channel;

	twopence_debug2("transaction_doio()\n");
	for (channel = trans->local_sink; channel; channel = channel->next)
		transaction_channel_doio(trans, channel);
	transaction_channel_list_purge(&trans->local_sink);

	for (channel = trans->local_source; channel; channel = channel->next)
		transaction_channel_doio(trans, channel);

	twopence_debug2("transaction_doio(): calling trans->send()\n");
	if (trans->send)
		trans->send(trans);

	/* Purge the source list *after* calling trans->send().
	 * This is because server_extract_file_send needs to detect
	 * the EOF condition on the source file and send an EOF packet.
	 * Once we wrap this inside the transaction_channel handling,
	 * then this requirement goes away. */
	transaction_channel_list_purge(&trans->local_source);
}

/*
 * This function is called from connection_doio when we have an incoming packet
 * for this transaction
 */
void
transaction_recv_packet(transaction_t *trans, const twopence_hdr_t *hdr, twopence_buf_t *payload)
{
	transaction_channel_t *sink;

	if (trans->done) {
		/* Coming late to the party, huh? */
		return;
	}

	if (trans->recv == NULL) {
		twopence_log_error("Unexpected packet type '%c' in transaction context\n", hdr->type);
		transaction_fail(trans, EPROTO);
		return;
	}

	sink = transaction_find_sink(trans, hdr->type);
	if (sink != NULL) {
		twopence_debug("received %u bytes of data\n", twopence_buf_count(payload));
		if (sink && !transaction_channel_write_data(sink, payload))
			transaction_fail(trans, errno);
		return;
	}

	trans->recv(trans, hdr, payload);
}


inline void
transaction_send_client(transaction_t *trans, twopence_buf_t *bp)
{
	const twopence_hdr_t *h = (const twopence_hdr_t *) twopence_buf_head(bp);

	twopence_debug("%s()\n", __func__);
	if (h)
		twopence_debug("%s: sending packet type %c, payload=%u\n", __func__, h->type, ntohs(h->len) - TWOPENCE_PROTO_HEADER_SIZE);
	twopence_sock_queue_xmit(trans->client_sock, bp);
}

void
transaction_send_major(transaction_t *trans, unsigned int code)
{
	twopence_debug("%s(id=%d, %d)\n", __func__, trans->id, code);
	assert(!trans->major_sent);
	transaction_send_client(trans, twopence_protocol_build_uint_packet_ps(&trans->ps, TWOPENCE_PROTO_TYPE_MAJOR, code));
	trans->major_sent = true;
}

void
transaction_send_minor(transaction_t *trans, unsigned int code)
{
	twopence_debug("%s(id=%d, %d)\n", __func__, trans->id, code);
	assert(!trans->minor_sent);
	transaction_send_client(trans, twopence_protocol_build_uint_packet_ps(&trans->ps, TWOPENCE_PROTO_TYPE_MINOR, code));
	trans->minor_sent = true;
}

void
transaction_send_status(transaction_t *trans, twopence_status_t *st)
{
	if (trans->done) {
		twopence_log_error("%s called twice\n", __func__);
		return;
	}
	transaction_send_client(trans, twopence_protocol_build_uint_packet(TWOPENCE_PROTO_TYPE_MAJOR, st->major));
	transaction_send_client(trans, twopence_protocol_build_uint_packet(TWOPENCE_PROTO_TYPE_MINOR, st->minor));
	trans->done = true;
}

void
transaction_fail(transaction_t *trans, int code)
{
	trans->done = true;
	if (!trans->major_sent) {
		transaction_send_major(trans, code);
		return;
	}
	if (!trans->minor_sent) {
		transaction_send_minor(trans, code);
		return;
	}
	twopence_debug("%s: already sent major and minor status\n", __func__);
	abort();
}

void
transaction_fail2(transaction_t *trans, int major, int minor)
{
	transaction_send_major(trans, major);
	transaction_send_minor(trans, minor);
	trans->done = 1;
}

/*
 * Command timed out.
 * We used to send an ETIME error, but it's been changed to
 * its own packet type.
 */
void
transaction_send_timeout(transaction_t *trans)
{
	twopence_buf_t *bp;

	bp = twopence_protocol_command_buffer_new();
	twopence_protocol_push_header_ps(bp, &trans->ps, TWOPENCE_PROTO_TYPE_TIMEOUT);
	transaction_send_client(trans, bp);
	trans->done = 1;
}

/*
 * Find the local sink corresponding to the given id.
 * For now, the "id" is a packet type, such as '0' or 'd'
 */
transaction_channel_t *
transaction_find_sink(transaction_t *trans, unsigned char id)
{
	transaction_channel_t *sink;

	for (sink = trans->local_sink; sink; sink = sink->next) {
		if (sink->id == id)
			return sink;
	}
	return NULL;
}

transaction_channel_t *
transaction_find_source(transaction_t *trans, unsigned char id)
{
	transaction_channel_t *channel;

	for (channel = trans->local_source; channel; channel = channel->next) {
		if (channel->id == id)
			return channel;
	}
	return NULL;
}

/*
 * We have received data from the client, and are asked to write it to a local file,
 * or to the command's stdin
 */
void
transaction_write_data(transaction_t *trans, twopence_buf_t *payload, unsigned char id)
{
	transaction_channel_t *sink;

	sink = transaction_find_sink(trans, id);
	if (sink && !transaction_channel_write_data(sink, payload))
		transaction_fail(trans, errno);
}

void
transaction_write_eof(transaction_t *trans)
{
	transaction_channel_t *sink;

	for (sink = trans->local_sink; sink; sink = sink->next)
		transaction_channel_write_eof(sink);
}
