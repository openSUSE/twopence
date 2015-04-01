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
};

static transaction_channel_t *	transaction_channel_from_fd(int);
static void			transaction_channel_free(transaction_channel_t *);
static bool			transaction_channel_write_data(transaction_channel_t *, twopence_buf_t *);
static bool			transaction_channel_write_eof(transaction_channel_t *);

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
	unsigned int i;

	/* Do not free trans->client_sock, we don't own it */

	transaction_close_sink(trans);

	for (i = 0; i < trans->num_local_sources; ++i) {
		twopence_sock_t *sock = trans->local_source[i];

		if (sock)
			twopence_sock_free(sock);
	}
	memset(trans, 0, sizeof(*trans));
	free(trans);
}

int
transaction_attach_local_sink(transaction_t *trans, int fd, unsigned char id)
{
	transaction_channel_t *sink;

	/* Make I/O to this file descriptor non-blocking */
	fcntl(fd, F_SETFL, O_NONBLOCK);

	sink = transaction_channel_from_fd(fd);
	sink->id = id;

	sink->next = trans->local_sink;
	trans->local_sink = sink;
	return 0;
}

void
transaction_close_sink(transaction_t *trans)
{
	while (trans->local_sink) {
		transaction_channel_t *sink = trans->local_sink;

		twopence_debug("closing sink for id %c\n", sink->id);
		trans->local_sink = sink->next;
		transaction_channel_free(sink);
	}
}

transaction_channel_t *
transaction_channel_from_fd(int fd)
{
	transaction_channel_t *sink;
	twopence_sock_t *sock;

	sock = twopence_sock_new_flags(fd, O_WRONLY);

	sink = calloc(1, sizeof(*sink));
	sink->socket = sock;

	return sink;
}

void
transaction_channel_free(transaction_channel_t *sink)
{
	if (sink->socket)
		twopence_sock_free(sink->socket);
	sink->socket = NULL;
	free(sink);
}

/*
 * Write data to the sink.
 * Note that the buffer is a temporary one on the stack, so if we
 * want to enqueue it to the socket, it has to be cloned first.
 * This is taken care of by twopence_sock_xmit_shared()
 */
bool
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

bool
transaction_channel_write_eof(transaction_channel_t *sink)
{
	twopence_sock_t *sock = sink->socket;

	if (sock && socket_shutdown_write(sock))
		return true;
	return false;
}

int
transaction_channel_poll(transaction_channel_t *sink, struct pollfd *pfd)
{
	twopence_sock_t *sock = sink->socket;

	if (sock && !socket_is_dead(sock)) {
		socket_prepare_poll(sock);
		if (socket_fill_poll(sock, pfd))
			return 1;
	}

	return 0;
}

int
transaction_channel_doio(transaction_t *trans, transaction_channel_t *sink)
{
	twopence_sock_t *sock = sink->socket;

	if (sock) {
		if (twopence_sock_doio(sock) < 0) {
			transaction_fail(trans, errno);
			socket_mark_dead(sock);
		}

		if (socket_is_dead(sock))
			return -1;
	}

	return 0;
}

twopence_sock_t *
transaction_attach_local_source(transaction_t *trans, int fd)
{
	twopence_sock_t *sock;

	if (trans->num_local_sources >= TRANSACTION_MAX_SOURCES) {
		twopence_log_error("%s: too many local sources\n", __func__);
		return NULL;
	}
	sock = twopence_sock_new_flags(fd, O_RDONLY);
	trans->local_source[trans->num_local_sources++] = sock;
	return sock;
}

void
transaction_close_source(transaction_t *trans, unsigned int i)
{
	twopence_sock_t *sock;

	if (i < trans->num_local_sources && trans->local_source[i]) {
		sock = trans->local_source[i];

		twopence_debug("closing command output fd %d%s\n", i + 1, socket_is_read_eof(sock)? ", EOF" : "");
		twopence_sock_free(sock);
		trans->local_source[i] = NULL;
	}
}

int
transaction_fill_poll(transaction_t *trans, struct pollfd *pfd, unsigned int max)
{
	unsigned int nfds = 0, i;
	twopence_sock_t *sock;

#if 0
	if (nfds < max
	 && (sock = trans->client_sock) != NULL
	 && socket_fill_poll(sock, pfd + nfds))
		nfds++;
#endif

	if (trans->local_sink != NULL) {
		transaction_channel_t *sink;

		for (sink = trans->local_sink; sink; sink = sink->next) {
			if (nfds < max && transaction_channel_poll(sink, pfd + nfds))
				nfds++;
		}
	}

	/* If the client socket's write queue is already bursting with data,
	 * refrain from queuing more until some of it has been drained */
	if (socket_xmit_queue_allowed(trans->client_sock)) {
		for (i = 0; i < trans->num_local_sources; ++i) {
			if ((sock = trans->local_source[i]) == NULL)
				continue;

			socket_prepare_poll(sock);
			if (nfds < max) {
				twopence_buf_t *bp;

				/* If needed, post a new receive buffer to the socket. */
				bp = socket_post_recvbuf_if_needed(sock, TWOPENCE_PROTO_MAX_PACKET);
				if (bp != NULL) {
					/* When we receive data from a command's output stream, or from
					 * a file that is being extracted, we do not want to copy
					 * the entire packet - instead, we reserve some room for the
					 * protocol header, which we just tack on once we have the data.
					 */
					twopence_buf_reserve_head(bp, TWOPENCE_PROTO_HEADER_SIZE);
				}
				if (socket_fill_poll(sock, pfd + nfds))
					nfds++;
			}
		}
	}

	return nfds;
}

void
transaction_doio(transaction_t *trans)
{
	unsigned int n;

	twopence_debug2("transaction_doio()\n");
	if (trans->local_sink != NULL) {
		transaction_channel_t *sink, **pos;

		pos = &trans->local_sink;
		while ((sink = *pos) != NULL) {
			if (transaction_channel_doio(trans, sink) < 0) {
				*pos = sink->next;
				transaction_channel_free(sink);
			} else {
				pos = &sink->next;
			}
		}
	}

	for (n = 0; n < trans->num_local_sources; ++n) {
		twopence_sock_t *sock;

		sock = trans->local_source[n];

		if (!sock)
			continue;

		if (twopence_sock_doio(sock) < 0) {
			transaction_fail(trans, errno);
			socket_mark_dead(sock);
		}
	}

	if (trans->send)
		trans->send(trans);

	for (n = 0; n < trans->num_local_sources; ++n) {
		twopence_sock_t *sock;

		sock = trans->local_source[n];

		if (sock && socket_is_dead(sock))
			transaction_close_source(trans, n);
	}

}

inline void
transaction_send_client(transaction_t *trans, twopence_buf_t *bp)
{
	const twopence_hdr_t *h = (const twopence_hdr_t *) twopence_buf_head(bp);

	twopence_debug("%s()\n", __func__);
	if (h)
		twopence_debug("%s: sending packet type %c, payload=%u\n", __func__, h->type, ntohs(h->len) - TWOPENCE_PROTO_HEADER_SIZE);
	socket_queue_xmit(trans->client_sock, bp);
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
static transaction_channel_t *
transaction_find_sink(transaction_t *trans, unsigned char id)
{
	transaction_channel_t *sink;

	for (sink = trans->local_sink; sink; sink = sink->next) {
		if (sink->id == id)
			return sink;
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

int
transaction_process(transaction_t *trans)
{
	unsigned int i;
	twopence_sock_t *sock;

	for (i = 0; i < trans->num_local_sources; ++i) {
		twopence_buf_t *bp;

		sock = trans->local_source[i];
		if (sock && (bp = socket_take_recvbuf(sock)) != NULL) {
			twopence_protocol_push_header_ps(bp, &trans->ps, TWOPENCE_PROTO_TYPE_STDOUT + i);
			socket_queue_xmit(trans->client_sock, bp);
		}
	}

	return true;
}
