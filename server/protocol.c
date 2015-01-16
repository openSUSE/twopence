/*
 * protocol and transaction routines for test server.
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


/*
 * Protocol handling functions
 */
void
protocol_build_header(buffer_t *bp, unsigned char type)
{
	unsigned int len = buffer_count(bp);
	header_t hdr;

	assert(len < 65536);

	hdr.type = type;
	hdr.pad = 0;
	hdr.len = htons(len);

	memcpy((void *) buffer_head(bp), &hdr, TWOPENCE_PROTO_HEADER_SIZE);
}

void
protocol_push_header(buffer_t *bp, unsigned char type)
{
	/* When we post buffers to the output streams of a command, for instance,
	 * we reserve the space needed for the header.
	 * When we get here, we want to use that space, so we need to
	 * change the head pointer back to the start of the buffer. */
	assert(bp->head == TWOPENCE_PROTO_HEADER_SIZE);
	bp->head = 0;

	protocol_build_header(bp, type);
}

buffer_t *
protocol_command_buffer_new()
{
	buffer_t *bp;

	bp = buffer_new(TWOPENCE_PROTO_MAX_PACKET);
	buffer_reserve_tail(bp, TWOPENCE_PROTO_HEADER_SIZE);

	/* Reserve head room */
	bp->head = bp->tail = TWOPENCE_PROTO_HEADER_SIZE;

	return bp;
}

buffer_t *
protocol_build_uint_packet(unsigned char type, unsigned int value)
{
	buffer_t *bp;
	char string[32];

	bp = protocol_command_buffer_new();

	snprintf(string, sizeof(string), "%u", value);
	buffer_puts(bp, string);

	protocol_push_header(bp, type);
	return bp;
}

buffer_t *
protocol_recv_buffer_new(void)
{
	buffer_t *bp;

	bp = buffer_new(TWOPENCE_PROTO_MAX_PACKET);
	buffer_reserve_tail(bp, TWOPENCE_PROTO_HEADER_SIZE);
	return bp;
}

bool
protocol_buffer_complete(const buffer_t *bp)
{
	const header_t *hdr;
	unsigned int len;

	len = buffer_count(bp);
	if (len < TWOPENCE_PROTO_HEADER_SIZE)
		return false;

	hdr = (header_t *) buffer_head(bp);
	if (len < htons(hdr->len))
		return false;
	return true;
}

const header_t *
protocol_dissect(buffer_t *bp, buffer_t *payload)
{
	header_t *hdr;
	unsigned int len;

	if (!(hdr = buffer_pull(bp, TWOPENCE_PROTO_HEADER_SIZE)))
		return NULL;

	len = ntohs(hdr->len);
	if (len < TWOPENCE_PROTO_HEADER_SIZE) {
		fprintf(stderr, "%s: invalid header, len=%u\n", __func__, len);
		return NULL;
	}

	len -= TWOPENCE_PROTO_HEADER_SIZE;
	if (buffer_count(bp) < len) {
		fprintf(stderr, "%s: called on incomplete packet (payload: header %u buffer %u)\n",
				__func__, len, buffer_count(bp));
		return NULL;
	}

	buffer_init_static(payload, (void *) buffer_head(bp), len);
	buffer_advance_head(bp, len);
	return hdr;
}

bool
protocol_dissect_string(buffer_t *bp, char *stringbuf, unsigned int size)
{
	unsigned int n, k, count;
	char *s;

	count = buffer_count(bp);
	s = (char *) buffer_head(bp);

	for (n = 0; n < count && isspace(s[n]); ++n)
		;

	for (k = 0; n < count && !isspace(s[n]); ++n) {
		if (k + 2 >= size)
			return false;
		stringbuf[k++] = s[n];
	}
	stringbuf[k] = '\0';

	for (; n < count && isspace(s[n]); ++n)
		;
	bp->head += n;

	TRACE("%s()=\"%s\"\n", __func__, stringbuf);
	return true;
}

bool
protocol_dissect_string_delim(buffer_t *bp, char *stringbuf, unsigned int size, char delimiter)
{
	unsigned int n = 0, k, count;
	char *s;

	count = buffer_count(bp);
	s = (char *) buffer_head(bp);

	for (k = 0; n < count && s[n] != delimiter; ++n) {
		if (k + 2 >= size)
			return false;
		stringbuf[k++] = s[n];
	}
	stringbuf[k] = '\0';
	bp->head += n;

	return true;
}

bool
protocol_dissect_uint(buffer_t *bp, unsigned int *retval)
{
	char buffer[32], *s;

	if (!protocol_dissect_string(bp, buffer, sizeof(buffer)))
		return false;

	*retval = strtoul(buffer, &s, 0);
	if (*s)
		return false;
	return true;
}

/*
 * Command handling
 */
transaction_t *
transaction_new(socket_t *client, unsigned int type, unsigned int id)
{
	transaction_t *trans;

	TRACE("%s('%c', %u)\n", __func__, type, id);
	trans = calloc(1, sizeof(*trans));
	trans->id = id;
	trans->type = type;
	trans->client_sock = client;
	return trans;
}

void
transaction_free(transaction_t *trans)
{
	unsigned int i;

	/* Do not free trans->client_sock, we don't own it */
	if (trans->local_sink)
		socket_free(trans->local_sink);
	for (i = 0; i < trans->num_local_sources; ++i) {
		socket_t *sock = trans->local_source[i];

		if (sock)
			socket_free(sock);
	}
	memset(trans, 0, sizeof(*trans));
	free(trans);
}

socket_t *
transaction_attach_local_sink(transaction_t *trans, int fd)
{
	socket_t *sock;

	if (trans->local_sink) {
		fprintf(stderr, "%s: duplicate local sink\n", __func__);
		return NULL;
	}
	sock = socket_new_flags(fd, O_WRONLY);
	trans->local_sink = sock;
	return sock;
}

void
transaction_close_sink(transaction_t *trans)
{
	if (trans->local_sink) {
		TRACE("closing command input fd\n");
		socket_free(trans->local_sink);
		trans->local_sink = NULL;
	}
}

socket_t *
transaction_attach_local_source(transaction_t *trans, int fd)
{
	socket_t *sock;

	if (trans->num_local_sources >= TRANSACTION_MAX_SOURCES) {
		fprintf(stderr, "%s: too many local sources\n", __func__);
		return NULL;
	}
	sock = socket_new_flags(fd, O_RDONLY);
	trans->local_source[trans->num_local_sources++] = sock;
	return sock;
}

void
transaction_close_source(transaction_t *trans, unsigned int i)
{
	socket_t *sock;

	if (i < trans->num_local_sources && trans->local_source[i]) {
		sock = trans->local_source[i];

		TRACE("closing command output fd %d%s\n", i + 1, socket_is_read_eof(sock)? ", EOF" : "");
		socket_free(sock);
		trans->local_source[i] = NULL;
	}
}

int
transaction_fill_poll(transaction_t *trans, struct pollfd *pfd, unsigned int max)
{
	unsigned int nfds = 0, i;
	socket_t *sock;

#if 0
	if (nfds < max
	 && (sock = trans->client_sock) != NULL
	 && socket_fill_poll(sock, pfd + nfds))
		nfds++;
#endif

	if ((sock = trans->local_sink) != NULL) {
		socket_prepare_poll(sock);
		if (nfds < max && socket_fill_poll(sock, pfd + nfds))
			nfds++;
	}

	/* If the client socket's write queue is already bursting with data,
	 * refrain from queuing more until some of it has been drained */
	if (socket_xmit_queue_allowed(trans->client_sock)) {
		for (i = 0; i < trans->num_local_sources; ++i) {
			if ((sock = trans->local_source[i]) == NULL)
				continue;

			socket_prepare_poll(sock);
			if (nfds < max) {
				buffer_t *bp;

				/* If needed, post a new receive buffer to the socket. */
				bp = socket_post_recvbuf_if_needed(sock, TWOPENCE_PROTO_MAX_PACKET);
				if (bp != NULL) {
					/* When we receive data from a command's output stream, or from
					 * a file that is being extracted, we do not want to copy
					 * the entire packet - instead, we reserve some room for the
					 * protocol header, which we just tack on once we have the data.
					 */
					buffer_reserve_head(bp, TWOPENCE_PROTO_HEADER_SIZE);
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
	socket_t *sock;
	unsigned int n;

	TRACE2("transaction_doio()\n");
	if ((sock = trans->local_sink) != NULL) {
		if (socket_doio(sock) < 0) {
			transaction_fail(trans, errno);
			socket_mark_dead(sock);
		}

		if (socket_is_dead(sock))
			transaction_close_sink(trans);
	}

	for (n = 0; n < trans->num_local_sources; ++n) {
		sock = trans->local_source[n];

		if (!sock)
			continue;

		if (socket_doio(sock) < 0) {
			transaction_fail(trans, errno);
			socket_mark_dead(sock);
		}

		if (socket_is_dead(sock))
			transaction_close_source(trans, n);
	}

	if (trans->send)
		trans->send(trans);
}

inline void
transaction_send_client(transaction_t *trans, buffer_t *bp)
{
	socket_queue_xmit(trans->client_sock, bp);
}

void
transaction_send_major(transaction_t *trans, unsigned int code)
{
	TRACE("%s(id=%d, %d)\n", __func__, trans->id, code);
	assert(!trans->major_sent);
	transaction_send_client(trans, protocol_build_uint_packet(PROTO_HDR_TYPE_MAJOR, code));
	trans->major_sent = true;
}

void
transaction_send_minor(transaction_t *trans, unsigned int code)
{
	TRACE("%s(id=%d, %d)\n", __func__, trans->id, code);
	assert(!trans->minor_sent);
	transaction_send_client(trans, protocol_build_uint_packet(PROTO_HDR_TYPE_MINOR, code));
	trans->minor_sent = true;
}

void
transaction_send_status(transaction_t *trans, twopence_status_t *st)
{
	if (trans->done) {
		fprintf(stderr, "%s called twice\n", __func__);
		return;
	}
	transaction_send_client(trans, protocol_build_uint_packet(PROTO_HDR_TYPE_MAJOR, st->major));
	transaction_send_client(trans, protocol_build_uint_packet(PROTO_HDR_TYPE_MINOR, st->minor));
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
	TRACE("%s: already sent major and minor status\n", __func__);
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
 * Command transaction: we have received data from the client,
 * and are asked to feed it to the command's standard input.
 *
 */
void
transaction_queue_stdin(transaction_t *trans, buffer_t *bp)
{
	socket_t *sock;

	if ((sock = trans->local_sink) == NULL) {
		buffer_free(bp);
		return;
	}

	socket_queue_xmit(sock, bp);
}

/*
 * File upload transaction: we have received data from the client,
 * and are asked to write it to a local file.
 *
 * The client has advised us about the maximum number of bytes
 * he will send; we stop after that amount and finish the
 * transation.
 */
bool
transaction_write_data(transaction_t *trans, buffer_t *payload)
{
	unsigned int count;
	socket_t *sock;
	int n;

	if ((sock = trans->local_sink) == NULL || !socket_xmit_queue_allowed(sock)) {
		/* FIXME: send status to client */
		return false;
	}

	count = buffer_count(payload);
	if (count > trans->byte_count) {
		fprintf(stderr, "%s: ignoring %u bytes of data\n", __func__, count - trans->byte_count);
		count = trans->byte_count;
	}

	TRACE("About to write %u bytes of data to local sink\n", count);
	if ((n = socket_write(sock, payload, count)) < 0) {
		transaction_fail(trans, errno);
		trans->done = true;
		return true;
	}
	assert(n == count);

	if (trans->byte_count) {
		trans->byte_count -= n;
		TRACE("wrote %u bytes, %u left\n", n, trans->byte_count);

		if (trans->byte_count == 0) {
			transaction_send_minor(trans, 0);
			socket_shutdown_write(sock);
			trans->done = true;
		}
	}

	return true;
}

bool
transaction_write_eof(transaction_t *trans)
{
	socket_t *sock;

	if ((sock = trans->local_sink) == NULL)
		return false;

	return socket_shutdown_write(sock);
}

int
transaction_process(transaction_t *trans)
{
	unsigned int i;
	socket_t *sock;

	for (i = 0; i < trans->num_local_sources; ++i) {
		buffer_t *bp;

		sock = trans->local_source[i];
		if (sock && (bp = socket_take_recvbuf(sock)) != NULL) {
			protocol_push_header(bp, PROTO_HDR_TYPE_STDOUT + i);
			socket_queue_xmit(trans->client_sock, bp);
		}
	}

	return true;
}
