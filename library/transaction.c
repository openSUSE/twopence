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
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h> /* for htons */

#include <pwd.h>
#include <grp.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
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

#include "protocol.h"
#include "transaction.h"


struct twopence_trans_channel {
	struct twopence_trans_channel *next;

	unsigned char		id;		/* corresponds to a packet type (eg '0' or 'd') */
	bool			sync;		/* if true, all writes are fully synchronous */

	twopence_sock_t *	socket;
	twopence_iostream_t *	stream;

	/* This is needed by the client side "inject" code:
	 * Before we start sending the actual file data, we want confirmation from
	 * the server that it was able to open the destination file.
	 * So even though we're adding the local sink channel early, we do not allow
	 * to transmit from right away. So initially, the channel is "plugged", and
	 * only when we receive a major status of 0, we will "unplug" it. */
	bool			plugged;

	struct {
	    void		(*read_eof)(twopence_transaction_t *, twopence_trans_channel_t *);
	    void		(*write_eof)(twopence_transaction_t *, twopence_trans_channel_t *);
	} callbacks;
};

/*
 * Transaction channel primitives
 */
static twopence_trans_channel_t *
twopence_transaction_channel_from_fd(int fd, int flags)
{
	twopence_trans_channel_t *sink;
	twopence_sock_t *sock;

	sock = twopence_sock_new_flags(fd, flags);

	sink = calloc(1, sizeof(*sink));
	sink->socket = sock;

	return sink;
}

static twopence_trans_channel_t *
twopence_transaction_channel_from_stream(twopence_iostream_t *stream, int flags)
{
	twopence_trans_channel_t *sink;

	sink = calloc(1, sizeof(*sink));
	sink->stream = stream;

	return sink;
}

static void
twopence_transaction_channel_free(twopence_trans_channel_t *sink)
{
	twopence_debug("%s(%c)", __func__, sink->id);
	if (sink->socket)
		twopence_sock_free(sink->socket);
	sink->socket = NULL;

	/* Do NOT free the iostream */

	free(sink);
}

bool
twopence_transaction_channel_is_read_eof(const twopence_trans_channel_t *channel)
{
	twopence_sock_t *sock = channel->socket;

	if (sock)
		return twopence_sock_is_read_eof(sock);
	if (channel->stream)
		return twopence_iostream_eof(channel->stream);
	return false;
}

void
twopence_transaction_channel_set_plugged(twopence_trans_channel_t *channel, bool plugged)
{
	channel->plugged = plugged;
}

void
twopence_transaction_channel_set_callback_read_eof(twopence_trans_channel_t *channel, void (*fn)(twopence_transaction_t *, twopence_trans_channel_t *))
{
	channel->callbacks.read_eof = fn;
}

void
twopence_transaction_channel_set_callback_write_eof(twopence_trans_channel_t *channel, void (*fn)(twopence_transaction_t *, twopence_trans_channel_t *))
{
	channel->callbacks.write_eof = fn;
}

static void
twopence_transaction_channel_list_purge(twopence_trans_channel_t **list)
{
	twopence_trans_channel_t *channel;

	while ((channel = *list) != NULL) {
		if (channel->socket && twopence_sock_is_dead(channel->socket)) {
			*list = channel->next;
			twopence_transaction_channel_free(channel);
		} else {
			list = &channel->next;
		}
	}
}

static void
twopence_transaction_channel_list_close(twopence_trans_channel_t **list, unsigned char id)
{
	twopence_trans_channel_t *channel;

	while ((channel = *list) != NULL) {
		if (id == 0 || channel->id == id) {
			*list = channel->next;
			twopence_transaction_channel_free(channel);
		} else {
			list = &channel->next;
		}
	}
}

/*
 * twopence transactions as used by our own on-the-wire protocol
 */
twopence_transaction_t *
twopence_transaction_new(twopence_sock_t *transport, unsigned int type, const twopence_protocol_state_t *ps)
{
	twopence_transaction_t *trans;

	trans = calloc(1, sizeof(*trans));
	trans->ps = *ps;
	trans->id = ps->xid;
	trans->type = type;
	trans->socket = transport;

	twopence_debug("%s: created new transaction", twopence_transaction_describe(trans));
	return trans;
}

void
twopence_transaction_free(twopence_transaction_t *trans)
{
	/* Do not free trans->socket, we don't own it */

	twopence_transaction_channel_list_close(&trans->local_sink, 0);
	twopence_transaction_channel_list_close(&trans->local_source, 0);

	memset(trans, 0, sizeof(*trans));
	free(trans);
}

const char *
twopence_transaction_describe(const twopence_transaction_t *trans)
{
	static char descbuf[64];
	const char *n;

	switch (trans->type) {
	case TWOPENCE_PROTO_TYPE_INJECT:
		n = "inject";
		break;
	case TWOPENCE_PROTO_TYPE_EXTRACT:
		n = "extract";
		break;
	case TWOPENCE_PROTO_TYPE_COMMAND:
		n = "command";
		break;
	default:
		snprintf(descbuf, sizeof(descbuf), "trans-type-%d/%u", trans->type, trans->ps.xid);
		return descbuf;
	}

	snprintf(descbuf, sizeof(descbuf), "%s/%u", n, trans->ps.xid);
	return descbuf;
}

void
twopence_transaction_set_dot_stream(twopence_transaction_t *trans, twopence_iostream_t *stream)
{
	if (trans->client.dot_stream != NULL && trans->client.dots_printed)
		twopence_iostream_putc(trans->client.dot_stream, '\n');
	trans->client.dot_stream = stream;
}

void
twopence_transaction_set_timeout(twopence_transaction_t *trans, long timeout)
{
	if (timeout > 0) {
		gettimeofday(&trans->client.deadline, NULL);
		trans->client.deadline.tv_sec += timeout;
	}
}

bool
twopence_transaction_update_timeout(const twopence_transaction_t *trans, twopence_timeout_t *tmo)
{
	return twopence_timeout_update(tmo, &trans->client.deadline);
}

static inline void
twopence_transaction_channel_trace_io(twopence_transaction_t *trans)
{
	if (trans->client.dot_stream) {
		twopence_iostream_putc(trans->client.dot_stream, '.');
		trans->client.dots_printed++;
	}
}

void
twopence_transaction_set_error(twopence_transaction_t *trans, int rc)
{
	twopence_debug("%s: set client side error to %d", twopence_transaction_describe(trans), rc);
	trans->client.exception = rc;
	trans->done = true;
}

unsigned int
twopence_transaction_num_channels(const twopence_transaction_t *trans)
{
	twopence_trans_channel_t *channel;
	unsigned int count = 0;

	for (channel = trans->local_sink; channel; channel = channel->next)
		count++;
	for (channel = trans->local_source; channel; channel = channel->next)
		count++;
	return count;
}

int
twopence_transaction_send_extract(twopence_transaction_t *trans, const char *user, const char *remote_name)
{
	twopence_buf_t *bp;

	bp = twopence_protocol_build_extract_packet(&trans->ps, user, remote_name);
	if (twopence_sock_xmit(trans->socket, bp) < 0)
		return TWOPENCE_SEND_COMMAND_ERROR;
	return 0;
}

int
twopence_transaction_send_inject(twopence_transaction_t *trans, const char *user, const char *remote_name, int remote_mode)
{
	twopence_buf_t *bp;

	bp = twopence_protocol_build_inject_packet(&trans->ps, user, remote_name, remote_mode);
	if (twopence_sock_xmit(trans->socket, bp) < 0)
		return TWOPENCE_SEND_COMMAND_ERROR;
	return 0;
}

int
twopence_transaction_send_command(twopence_transaction_t *trans, const char *user, const char *linux_command, long timeout)
{
	twopence_buf_t *bp;

	bp = twopence_protocol_build_command_packet(&trans->ps, user, linux_command, timeout);
	if (twopence_sock_xmit(trans->socket, bp) < 0)
		return TWOPENCE_SEND_COMMAND_ERROR;
	return 0;
}

/* FIXME: swap fd and id arguments */
twopence_trans_channel_t *
twopence_transaction_attach_local_sink(twopence_transaction_t *trans, int fd, unsigned char id)
{
	twopence_trans_channel_t *sink;

	/* Make I/O to this file descriptor non-blocking */
	fcntl(fd, F_SETFL, O_NONBLOCK);

	sink = twopence_transaction_channel_from_fd(fd, O_WRONLY);
	sink->id = id;

	sink->next = trans->local_sink;
	trans->local_sink = sink;
	return sink;
}

twopence_trans_channel_t *
twopence_transaction_attach_local_sink_stream(twopence_transaction_t *trans, unsigned char id, twopence_iostream_t *stream)
{
	twopence_trans_channel_t *sink;
	int fd;

	fd = twopence_iostream_getfd(stream);
	if (fd >= 0) {
		sink = twopence_transaction_attach_local_sink(trans, fd, id);
		twopence_sock_set_noclose(sink->socket);
		return sink;
	}

	sink = twopence_transaction_channel_from_stream(stream, O_WRONLY);
	sink->id = id;

	sink->next = trans->local_sink;
	trans->local_sink = sink;
	return sink;
}

void
twopence_transaction_close_sink(twopence_transaction_t *trans, unsigned char id)
{
	twopence_debug("%s: close sink %c\n", twopence_transaction_describe(trans), id? : '-');
	twopence_transaction_channel_list_close(&trans->local_sink, id);
}

twopence_trans_channel_t *
twopence_transaction_attach_local_source(twopence_transaction_t *trans, int fd, unsigned char channel_id)
{
	twopence_trans_channel_t *source;

	/* Make I/O to this file descriptor non-blocking */
	fcntl(fd, F_SETFL, O_NONBLOCK);

	source = twopence_transaction_channel_from_fd(fd, O_RDONLY);
	source->id = channel_id;

	source->next = trans->local_source;
	trans->local_source = source;
	return source;
}

twopence_trans_channel_t *
twopence_transaction_attach_local_source_stream(twopence_transaction_t *trans, unsigned char id, twopence_iostream_t *stream)
{
	twopence_trans_channel_t *source;
	int fd;

	fd = twopence_iostream_getfd(stream);
	if (fd >= 0) {
		source = twopence_transaction_attach_local_source(trans, fd, id);
		twopence_sock_set_noclose(source->socket);
		return source;
	}

	source = twopence_transaction_channel_from_stream(stream, O_RDONLY);
	source->id = id;

	source->next = trans->local_source;
	trans->local_source = source;
	return source;
}

void
twopence_transaction_close_source(twopence_transaction_t *trans, unsigned char id)
{
	twopence_debug("%s: close source %c\n", twopence_transaction_describe(trans), id? : '-');
	twopence_transaction_channel_list_close(&trans->local_source, id);
}

/*
 * Write data to the sink.
 * Note that the buffer is a temporary one on the stack, so if we
 * want to enqueue it to the socket, it has to be cloned first.
 * This is taken care of by twopence_sock_xmit_shared()
 */
static bool
twopence_transaction_channel_write_data(twopence_transaction_t *trans, twopence_trans_channel_t *sink, twopence_buf_t *payload)
{
	unsigned int count = twopence_buf_count(payload);
	twopence_iostream_t *stream;
	twopence_sock_t *sock;

	twopence_debug("About to write %u bytes of data to local sink\n", count);
	if ((sock = sink->socket) != NULL) {
		if (twopence_sock_xmit_shared(sock, payload) < 0)
			return false;
	} else
	if ((stream = sink->stream) != NULL) {
		twopence_iostream_write(stream, twopence_buf_head(payload), count);
		twopence_buf_advance_head(payload, count);
	}

	twopence_transaction_channel_trace_io(trans);
	return true;
}

int
twopence_transaction_channel_flush(twopence_trans_channel_t *sink)
{
	twopence_sock_t *sock;

	if ((sock = sink->socket) == NULL)
		return 0;

	if (twopence_sock_xmit_queue_bytes(sock) == 0)
		return 0;

	twopence_debug("Flushing %u bytes queued to channel %c\n", twopence_sock_xmit_queue_bytes(sock), sink->id);
	return twopence_sock_xmit_queue_flush(sock);
}

static void
twopence_transaction_channel_write_eof(twopence_trans_channel_t *sink)
{
	twopence_sock_t *sock = sink->socket;

	if (sock)
		twopence_sock_shutdown_write(sock);
}

int
twopence_transaction_channel_poll(twopence_trans_channel_t *channel, struct pollfd *pfd)
{
	twopence_sock_t *sock = channel->socket;

	if (sock && !twopence_sock_is_dead(sock)) {
		twopence_buf_t *bp;

		twopence_sock_prepare_poll(sock);

		/* If needed, post a new receive buffer to the socket.
		 * Note: this is a NOP for sink channels, as their socket
		 * already has read_eof set, so that a recvbuf is never
		 * posted to it.
		 */
		if (!channel->plugged
		 && !twopence_sock_is_read_eof(sock)
		 && (bp = twopence_sock_get_recvbuf(sock)) == NULL) {
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

/* This should be executed for source channels only! */
static void
twopence_transaction_channel_forward(twopence_transaction_t *trans, twopence_trans_channel_t *channel)
{
	twopence_iostream_t *stream = channel->stream;

	if (!channel->plugged && stream != NULL) {
		while (twopence_sock_xmit_queue_allowed(trans->socket) && !twopence_iostream_eof(stream)) {
			twopence_buf_t *bp;
			int count;

			bp = twopence_protocol_command_buffer_new();
			do {
				count = twopence_iostream_read(stream,
						twopence_buf_tail(bp),
						twopence_buf_tailroom(bp));
			} while (count < 0 && errno == EINTR);

			if (count > 0) {
				twopence_buf_advance_tail(bp, count);
				twopence_protocol_push_header_ps(bp, &trans->ps, channel->id);
				twopence_transaction_send_client(trans, bp);

				twopence_transaction_channel_trace_io(trans);
				continue;
			}

			twopence_buf_free(bp);
			if (count == 0)
				break;
			if (count < 0) {
				if (errno != EAGAIN) {
					twopence_log_error("%s: error on channel %c", twopence_transaction_describe(trans), channel->id);
					twopence_transaction_set_error(trans, count);
				}
				return;
			}
		}

		if (twopence_iostream_eof(stream) && channel->callbacks.read_eof) {
			twopence_debug("%s: EOF on channel %c", twopence_transaction_describe(trans), channel->id);
			channel->callbacks.read_eof(trans, channel);
			channel->callbacks.read_eof = NULL;
			channel->stream = NULL;
		}
	}
}

static void
twopence_transaction_channel_doio(twopence_transaction_t *trans, twopence_trans_channel_t *channel)
{
	twopence_sock_t *sock = channel->socket;

	if (sock) {
		twopence_buf_t *bp;

		if (twopence_sock_doio(sock) < 0) {
			twopence_transaction_fail(trans, errno);
			twopence_sock_mark_dead(sock);
			return;
		}

		/* Only source channels will even have a recv buffer posted
		 * to them. If that is non-empty, queue it to the transport
		 * socket. */
		if ((bp = twopence_sock_take_recvbuf(sock)) != NULL) {
			unsigned int count = twopence_buf_count(bp) - TWOPENCE_PROTO_HEADER_SIZE;

			twopence_debug2("%s: %u bytes from local source %c", twopence_transaction_describe(trans), count, channel->id);
			twopence_protocol_push_header_ps(bp, &trans->ps, channel->id);
			twopence_sock_queue_xmit(trans->socket, bp);

			twopence_transaction_channel_trace_io(trans);
		}

		/* For file extractions, we want to send an EOF packet
		 * when the file has been transmitted in its entirety.
		 */
		if (twopence_sock_is_read_eof(sock) && channel->callbacks.read_eof) {
			twopence_debug("%s: EOF on channel %c", twopence_transaction_describe(trans), channel->id);
			channel->callbacks.read_eof(trans, channel);
			channel->callbacks.read_eof = NULL;
		}
	}
}

int
twopence_transaction_fill_poll(twopence_transaction_t *trans, struct pollfd *pfd, unsigned int max)
{
	unsigned int nfds = 0;

	if (trans->local_sink != NULL) {
		twopence_trans_channel_t *sink;

		for (sink = trans->local_sink; sink; sink = sink->next) {
			if (nfds < max && twopence_transaction_channel_poll(sink, pfd + nfds))
				nfds++;
		}
	}

	/* If the client socket's write queue is already bursting with data,
	 * refrain from queuing more until some of it has been drained */
	if (twopence_sock_xmit_queue_allowed(trans->socket)) {
		twopence_trans_channel_t *source;

		for (source = trans->local_source; source; source = source->next) {
			if (nfds < max && twopence_transaction_channel_poll(source, pfd + nfds)) {
				nfds++;
			} else {
				/* This is a source not backed by a file descriptor but
				 * something else (such as a buffer).
				 * This means we cannot poll, so we just forward all data
				 * we have. */
				twopence_transaction_channel_forward(trans, source);
			}
		}
	}

	return nfds;
}

void
twopence_transaction_doio(twopence_transaction_t *trans)
{
	twopence_trans_channel_t *channel;

	twopence_debug2("%s: twopence_transaction_doio()\n", twopence_transaction_describe(trans));
	for (channel = trans->local_sink; channel; channel = channel->next)
		twopence_transaction_channel_doio(trans, channel);
	twopence_transaction_channel_list_purge(&trans->local_sink);

	for (channel = trans->local_source; channel; channel = channel->next)
		twopence_transaction_channel_doio(trans, channel);

	twopence_debug2("twopence_transaction_doio(): calling trans->send()\n");
	if (trans->send)
		trans->send(trans);

	/* Purge the source list *after* calling trans->send().
	 * This is because server_extract_file_send needs to detect
	 * the EOF condition on the source file and send an EOF packet.
	 * Once we wrap this inside the twopence_trans_channel handling,
	 * then this requirement goes away. */
	twopence_transaction_channel_list_purge(&trans->local_source);
}

/*
 * This function is called from connection_doio when we have an incoming packet
 * for this transaction
 */
void
twopence_transaction_recv_packet(twopence_transaction_t *trans, const twopence_hdr_t *hdr, twopence_buf_t *payload)
{
	twopence_trans_channel_t *sink;

	if (trans->done) {
		/* Coming late to the party, huh? */
		return;
	}

	sink = twopence_transaction_find_sink(trans, hdr->type);
	if (sink != NULL) {
		twopence_debug("%s: received %u bytes of data on channel %c\n",
				twopence_transaction_describe(trans), twopence_buf_count(payload), sink->id);
		if (sink && !twopence_transaction_channel_write_data(trans, sink, payload))
			twopence_transaction_fail(trans, errno);
		return;
	}

	if (hdr->type == TWOPENCE_PROTO_TYPE_EOF
	 && (sink = trans->local_sink) != NULL
	 && sink->callbacks.write_eof) {
		twopence_debug("%s: received EOF", twopence_transaction_describe(trans));

		/* Passing the EOF indication to what is essentially a random local sink
		 * is not correct, but right now, we're just handling one local sink at most. */
		twopence_transaction_channel_write_eof(sink);
		sink->callbacks.write_eof(trans, sink);
		sink->callbacks.write_eof = NULL;
		return;
	}

	if (trans->recv == NULL) {
		twopence_log_error("%s: unexpected packet type '%c'\n", twopence_transaction_describe(trans), hdr->type);
		twopence_transaction_fail(trans, EPROTO);
		return;
	}

	trans->recv(trans, hdr, payload);
}


inline void
twopence_transaction_send_client(twopence_transaction_t *trans, twopence_buf_t *bp)
{
	const twopence_hdr_t *h = (const twopence_hdr_t *) twopence_buf_head(bp);

	if (h == NULL)
		return;

	twopence_debug("%s: sending packet type %c, payload=%u\n", twopence_transaction_describe(trans), h->type, ntohs(h->len) - TWOPENCE_PROTO_HEADER_SIZE);
	twopence_sock_queue_xmit(trans->socket, bp);
}

void
twopence_transaction_send_major(twopence_transaction_t *trans, unsigned int code)
{
	twopence_debug("%s: send status.major=%u", twopence_transaction_describe(trans), code);
	assert(!trans->major_sent);
	twopence_transaction_send_client(trans, twopence_protocol_build_uint_packet_ps(&trans->ps, TWOPENCE_PROTO_TYPE_MAJOR, code));
	trans->major_sent = true;
}

void
twopence_transaction_send_minor(twopence_transaction_t *trans, unsigned int code)
{
	twopence_debug("%s: send status.minor=%u", twopence_transaction_describe(trans), code);
	assert(!trans->minor_sent);
	twopence_transaction_send_client(trans, twopence_protocol_build_uint_packet_ps(&trans->ps, TWOPENCE_PROTO_TYPE_MINOR, code));
	trans->minor_sent = true;
}

void
twopence_transaction_send_status(twopence_transaction_t *trans, twopence_status_t *st)
{
	if (trans->done) {
		twopence_log_error("%s called twice\n", __func__);
		return;
	}
	twopence_transaction_send_client(trans, twopence_protocol_build_uint_packet(TWOPENCE_PROTO_TYPE_MAJOR, st->major));
	twopence_transaction_send_client(trans, twopence_protocol_build_uint_packet(TWOPENCE_PROTO_TYPE_MINOR, st->minor));
	trans->done = true;
}

void
twopence_transaction_fail(twopence_transaction_t *trans, int code)
{
	trans->done = true;
	if (!trans->major_sent) {
		twopence_transaction_send_major(trans, code);
		return;
	}
	if (!trans->minor_sent) {
		twopence_transaction_send_minor(trans, code);
		return;
	}
	twopence_debug("%s: already sent major and minor status\n", __func__);
	abort();
}

void
twopence_transaction_fail2(twopence_transaction_t *trans, int major, int minor)
{
	twopence_transaction_send_major(trans, major);
	twopence_transaction_send_minor(trans, minor);
	trans->done = 1;
}

/*
 * Command timed out.
 * We used to send an ETIME error, but it's been changed to
 * its own packet type.
 */
void
twopence_transaction_send_timeout(twopence_transaction_t *trans)
{
	twopence_buf_t *bp;

	bp = twopence_protocol_command_buffer_new();
	twopence_protocol_push_header_ps(bp, &trans->ps, TWOPENCE_PROTO_TYPE_TIMEOUT);
	twopence_transaction_send_client(trans, bp);
	trans->done = 1;
}

/*
 * Find the local sink corresponding to the given id.
 * For now, the "id" is a packet type, such as '0' or 'd'
 */
twopence_trans_channel_t *
twopence_transaction_find_sink(twopence_transaction_t *trans, unsigned char id)
{
	twopence_trans_channel_t *sink;

	for (sink = trans->local_sink; sink; sink = sink->next) {
		if (sink->id == id)
			return sink;
	}
	return NULL;
}

twopence_trans_channel_t *
twopence_transaction_find_source(twopence_transaction_t *trans, unsigned char id)
{
	twopence_trans_channel_t *channel;

	for (channel = trans->local_source; channel; channel = channel->next) {
		if (channel->id == id)
			return channel;
	}
	return NULL;
}
