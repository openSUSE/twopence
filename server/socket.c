/*
 * I/O routines for test server.
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

struct queue {
	unsigned int	bytes;
	unsigned int	max_bytes;

	packet_t *	head;
	packet_t **	tail;
};

struct socket {
	int		fd;

	unsigned int	bytes_sent;

	queue_t		xmit_queue;
	buffer_t *	recv_buf;

	bool		read_eof;
	unsigned char	write_eof;

	struct pollfd *	poll_data;
};

struct packet {
	packet_t *	next;

	unsigned int	bytes;
	buffer_t *	buffer;
};

#define SHUTDOWN_WANTED		1
#define SHUTDOWN_SENT		2

void
buffer_init(buffer_t *bp)
{
	memset(bp, 0, sizeof(*bp));
}

void
buffer_init_static(buffer_t *bp, void *data, size_t len)
{
	memset(bp, 0, sizeof(*bp));
	bp->base = data;
	bp->tail = len;
}

void
buffer_destroy(buffer_t *bp)
{
	buffer_init(bp);
}

buffer_t *
buffer_new(size_t size)
{
	buffer_t *bp;

	bp = calloc(1, sizeof(*bp) + size);
	bp->base = (char *)(bp + 1);
	bp->size = size;
	return bp;
}

buffer_t *
buffer_clone(buffer_t *bp)
{
	unsigned int count = bp->tail - bp->head;
	buffer_t *clone;

	clone = buffer_new(count);
	buffer_append(clone, bp->base, count);
	return clone;
}

void
buffer_free(buffer_t *bp)
{
	buffer_destroy(bp);
	free(bp);
}

const void *
buffer_head(const buffer_t *bp)
{
	return bp->base + bp->head;
}

void *
buffer_tail(const buffer_t *bp)
{
	return bp->base + bp->tail;
}

unsigned int
buffer_tailroom(const buffer_t *bp)
{
	return bp->size - bp->tail;
}

unsigned int
buffer_tailroom_max(const buffer_t *bp)
{
	return bp->size - bp->tail;
}

unsigned int
buffer_count(const buffer_t *bp)
{
	return bp->tail - bp->head;
}

void *
buffer_pull(buffer_t *bp, unsigned int len)
{
	void *h = bp->base + bp->head;

	if (buffer_count(bp) < len)
		return NULL;
	bp->head += len;
	return h;
}

bool
buffer_push(buffer_t *bp, void *data, unsigned int len)
{
	if (bp->head < len)
		return false;
	bp->head -= len;
	memcpy(bp->base + bp->head, data, len);
	return true;
}

#if 0
bool
buffer_resize(buffer_t *bp, unsigned int want_size)
{
	unsigned int new_size;

	if (want_size <= bp->size)
		return true;

	if (want_size >= bp->max_size)
		return false;

	for (new_size = bp->size * 2; new_size < want_size; new_size *= 2)
		;

	if (new_size < BUFFER_MIN_SIZE)
		new_size = BUFFER_MIN_SIZE;
	if (new_size > bp->max_size)
		new_size = bp->max_size;

	assert(want_size <= new_size);

	bp->base = realloc(bp->base, new_size);
	assert(bp->base);

	bp->size = new_size;
	return true;
}
#endif

void
buffer_reserve_head(buffer_t *bp, unsigned int amount)
{
	assert(bp->head == bp->tail && bp->size > amount);
	bp->head = bp->tail = amount;
}

void *
buffer_reserve_tail(buffer_t *bp, unsigned int len)
{
	if (buffer_tailroom(bp) < len)
		return NULL;

	return bp->base + bp->tail;
}

void
buffer_advance_tail(buffer_t *bp, unsigned int len)
{
	assert(buffer_tailroom(bp) >= len);
	bp->tail += len;
}

void
buffer_advance_head(buffer_t *bp, unsigned int len)
{
	assert(buffer_count(bp) >= len);
	bp->head += len;
}

void
buffer_truncate(buffer_t *bp, unsigned int len)
{
	if (len < buffer_count(bp))
		bp->tail = bp->head + len;
}

bool
buffer_append(buffer_t *bp, const void *data, unsigned int len)
{
	if (!buffer_reserve_tail(bp, len))
		return false;

	memcpy(bp->base + bp->tail, data, len);
	bp->tail += len;
	return true;
}

bool
buffer_puts(buffer_t *bp, const char *s)
{
	if (!s)
		return true;
	return buffer_append(bp, s, strlen(s) + 1);
}

void
buffer_reset(buffer_t *bp)
{
	assert(buffer_count(bp) == 0);
	bp->head = bp->tail = 0;
}

void
buffer_compact(buffer_t *bp)
{
	unsigned int count = buffer_count(bp);

	if (count)
		memmove(bp->base, bp->base + bp->head, count);
	bp->head = 0;
	bp->tail = count;
}

packet_t *
packet_new(buffer_t *bp)
{
	packet_t *pkt;

	pkt = calloc(1, sizeof(*pkt));
	pkt->buffer = bp;
	pkt->bytes = buffer_count(bp);
	return pkt;
}

void
packet_free(packet_t *pkt)
{
	if (pkt->buffer)
		buffer_free(pkt->buffer);
	free(pkt);
}

void
queue_init(queue_t *queue)
{
	queue->head = NULL;
	queue->tail = &queue->head;
	queue->max_bytes = 16 * 65536;
}

void
queue_destroy(queue_t *queue)
{
	packet_t *pkt;

	while ((pkt = queue->head) != NULL) {
		queue->head = pkt->next;
		packet_free(pkt);
	}
	queue->tail = &queue->head;
}

bool
queue_empty(const queue_t *queue)
{
	return queue->head == NULL;
}

void
queue_append(queue_t *queue, packet_t *pkt)
{
	*queue->tail = pkt;
	queue->tail = &pkt->next;
	queue->bytes += pkt->bytes;
}

packet_t *
queue_head(const queue_t *queue)
{
	return queue->head;
}

bool
queue_full(const queue_t *queue)
{
	return queue->max_bytes == 0 || queue->bytes >= queue->max_bytes;
}

packet_t *
queue_dequeue(queue_t *queue)
{
	packet_t *pkt;

	if ((pkt = queue->head) != NULL) {
		assert(pkt->bytes <= queue->bytes);
		queue->bytes -= pkt->bytes;

		queue->head = pkt->next;
		if (queue->head == NULL)
			queue->tail = &queue->head;
	}
	return pkt;
}

socket_t *
__socket_new(int fd)
{
	socket_t *sock;
	int f;

	sock = calloc(1, sizeof(*sock));
	sock->fd = fd;

	/* Set to nonblocking IO */
	if ((f = fcntl(fd, F_GETFL)) < 0
	 || fcntl(fd, F_SETFL, f | O_NONBLOCK) < 0) {
		fprintf(stderr, "socket_new: trouble setting socket to nonblocking I/O: %m\n");
		/* Continue anyway */
	}

	queue_init(&sock->xmit_queue);
	return sock;
}

socket_t *
socket_new(int fd)
{
	return __socket_new(fd);
}

socket_t *
socket_new_flags(int fd, int oflags)
{
	socket_t *sock;

	sock = __socket_new(fd);
	switch (oflags & O_ACCMODE) {
	case O_RDONLY:
		sock->write_eof = SHUTDOWN_SENT;
		break;

	case O_WRONLY:
		sock->read_eof = true;
		break;

	default: ;
	}

	return sock;
}

void
socket_free(socket_t *sock)
{
	TRACE("%s(%d)\n", __func__, sock->fd);
	if (sock->fd >= 0)
		close(sock->fd);

	queue_destroy(&sock->xmit_queue);
	if (sock->recv_buf)
		buffer_free(sock->recv_buf);
	free(sock);
}

int
socket_id(const socket_t *sock)
{
	return sock->fd;
}

int
socket_recv_buffer(socket_t *sock, buffer_t *bp)
{
	unsigned int count;
	int n;

	count = buffer_tailroom(bp);
	if (count == 0) {
		TRACE("%s: no tailroom in buffer", __func__);
		errno = ENOBUFS;
		return -1;
	}

#if 0
	/* Testing: simulate serial pipe behavior - large packets get chopped
	 * up into 4k chunks */
	if (count > 4096)
		count = 4096;
#endif

	n = read(sock->fd, buffer_tail(bp), count);
	if (n > 0)
		buffer_advance_tail(bp, n);
	else if (n < 0)
		TRACE("%s: recv() returns error: %m", __func__);
	return n;
}

buffer_t *
socket_take_recvbuf(socket_t *sock)
{
	buffer_t *bp;

	if ((bp = sock->recv_buf) == NULL
	 || buffer_count(bp) == 0)
		return NULL;

	sock->recv_buf = NULL;
	return bp;
}

buffer_t *
socket_get_recvbuf(socket_t *sock)
{
	return sock->recv_buf;
}

void
socket_post_recvbuf(socket_t *sock, buffer_t *bp)
{
	if (sock->recv_buf != NULL) {
		assert(buffer_count(sock->recv_buf) == 0);
		buffer_free(sock->recv_buf);
	}
	sock->recv_buf = bp;
}

buffer_t *
socket_post_recvbuf_if_needed(socket_t *sock, unsigned int size)
{
	/* If the socket is at EOF, or if we already have posted a
	 * receive buffer, there's no need to post a new one.
	 * Return NULL.
	 */
	if (sock->read_eof || sock->recv_buf != NULL)
		return NULL;

	sock->recv_buf = buffer_new(size);
	return sock->recv_buf;
}

int
socket_write(socket_t *sock, buffer_t *bp, unsigned int count)
{
	int n;

	if (count == 0)
		return 0;

	if (buffer_count(bp) < count)
		count = buffer_count(bp);

	n = write(sock->fd, buffer_head(bp), count);
	if (n > 0)
		sock->bytes_sent += n;
	return n;
}

int
socket_send_buffer(socket_t *sock, buffer_t *bp)
{
	int n;

	n = socket_write(sock, bp, buffer_count(bp));
	if (n > 0) {
		TRACE2("%s(%d): wrote %u bytes\n", __func__, sock->fd, n);
		buffer_advance_head(bp, n);
	}
	return n;
}

void
socket_queue_xmit(socket_t *sock, buffer_t *bp)
{
	packet_t *pkt;

	if (sock->write_eof) {
		fprintf(stderr, "%s: attempt to queue data after write shutdown\n", __func__);
		buffer_free(bp);
		return;
	}

	pkt = packet_new(bp);
	queue_append(&sock->xmit_queue, pkt);
}

void
socket_send_or_queue(socket_t *sock, buffer_t *bp)
{
	packet_t *pkt;

	if (sock->write_eof) {
		fprintf(stderr, "%s: attempt to queue data after write shutdown\n", __func__);
		return;
	}

	/* If nothing is queued to the socket, we might as well try to
	 * send this data directly. */
	if (queue_empty(&sock->xmit_queue))
		(void) socket_send_buffer(sock, bp);

	if (buffer_count(bp) != 0) {
		pkt = packet_new(buffer_clone(bp));
		queue_append(&sock->xmit_queue, pkt);
	}
}

int
socket_send_queued(socket_t *sock)
{
	packet_t *pkt;
	int n;

	if ((pkt = queue_head(&sock->xmit_queue)) == NULL)
		return 0;

	n = socket_send_buffer(sock, pkt->buffer);
	if (buffer_count(pkt->buffer) == 0) {
		/* Sent the complete buffer */
		queue_dequeue(&sock->xmit_queue);
		packet_free(pkt);
	}

	return n;
}

unsigned int
socket_xmit_queue_bytes(socket_t *sock)
{
	return sock->xmit_queue.bytes;
}

bool
socket_xmit_queue_allowed(const socket_t *sock)
{
	if (sock->write_eof) {
		/* This is different from socket_is_write_eof.
		 * socket_is_write_eof checks whether we can transmit any data to the
		 * socket itself.
		 * This function checks whether we are allowed to queue more data
		 * to the socket. Queuing data is also disallowed if the transaction
		 * indicated that we should shut down this socket for writing as
		 * soon as we have drained the xmit buffers.
		 */
		return false;
	}

	if (queue_full(&sock->xmit_queue))
		return false;

	return true;
}

static bool
__socket_try_shutdown(socket_t *sock)
{
	if (queue_empty(&sock->xmit_queue)) {
		shutdown(sock->fd, SHUT_WR);
		sock->write_eof = SHUTDOWN_SENT;
		return true;
	}
	return false;
}

bool
socket_shutdown_write(socket_t *sock)
{
	if (sock->write_eof)
		return true;

	sock->write_eof = SHUTDOWN_WANTED;
	__socket_try_shutdown(sock);
	return true;
}

void
socket_mark_dead(socket_t *sock)
{
	sock->read_eof = true;
	sock->write_eof = SHUTDOWN_SENT;
}

bool
socket_is_read_eof(const socket_t *sock)
{
	return sock->read_eof;
}

bool
socket_is_write_eof(const socket_t *sock)
{
	return sock->write_eof == SHUTDOWN_SENT;
}

bool
socket_is_dead(socket_t *sock)
{
	return sock->read_eof && sock->write_eof == SHUTDOWN_SENT;
}

static const char *
socket_state_desc(const socket_t *sock)
{
	if (sock->read_eof) {
		switch (sock->write_eof) {
		case 0:
			return "write-only";
		case SHUTDOWN_WANTED:
			return "draining";
		case SHUTDOWN_SENT:
			return "dead";
		}
	} else {
		switch (sock->write_eof) {
		case 0:
			return "read-write";
		case SHUTDOWN_WANTED:
			return "read-draining";
		case SHUTDOWN_SENT:
			return "read-only";
		}
	}
	return "undefined";
}

static const char *
socket_queue_desc(const socket_t *sock)
{
	static char buffer[60];
	unsigned int recv_bytes = sock->recv_buf? buffer_count(sock->recv_buf) : 0;
	unsigned int send_bytes = sock->xmit_queue.bytes;

	if (recv_bytes == 0 && send_bytes == 0)
		return "";

	if (recv_bytes == 0)
		snprintf(buffer, sizeof(buffer), ", pending send=%u", send_bytes);
	else
	if (send_bytes == 0)
		snprintf(buffer, sizeof(buffer), ", pending recv=%u", recv_bytes);
	else
		snprintf(buffer, sizeof(buffer), ", pending recv=%u send=%u", recv_bytes, send_bytes);
	return buffer;
}

static const char *
poll_bit_string(int events)
{
	static struct {
		int bit; const char *name;
	} bitnames[] = {
		{ POLLIN, "POLLIN" },
		{ POLLOUT, "POLLOUT" },
		{ POLLERR, "POLLERR" },
		{ POLLHUP, "POLLHUP" },
		{ 0, NULL }
	};
	static char buffer[60];
	char sepa = '<';
	int k, len = 0;

	for (k = 0; bitnames[k].bit; ++k) {
		if (events & bitnames[k].bit) {
			buffer[len++] = sepa;
			strcpy(buffer + len, bitnames[k].name);
			len = strlen(buffer);
			sepa = '|';
		}
	}

	buffer[len++] = '>';
	buffer[len] = '\0';
	return buffer;
}

void
socket_prepare_poll(socket_t *sock)
{
	sock->poll_data = NULL;
}

bool
socket_fill_poll(socket_t *sock, struct pollfd *pfd)
{
	sock->poll_data = NULL;

	memset(pfd, 0, sizeof(*pfd));
	if (sock->fd < 0)
		return false;

	if (sock->write_eof != SHUTDOWN_SENT) {
		if (!queue_empty(&sock->xmit_queue))
			pfd->events |= POLLOUT;
	}
	if (!sock->read_eof) {
		if (sock->recv_buf != NULL && buffer_tailroom_max(sock->recv_buf) != 0)
			pfd->events |= POLLIN;
	}

	if (pfd->events == 0)
		return false;

	TRACE2("%s(fd=%d, %s%s): events=%s\n", __func__, sock->fd, socket_state_desc(sock), socket_queue_desc(sock), poll_bit_string(pfd->events));
	sock->poll_data = pfd;
	pfd->fd = sock->fd;
	return true;
}

int
socket_doio(socket_t *sock)
{
	struct pollfd *pfd;
	int n;

	if ((pfd = sock->poll_data) == NULL)
		return 0;
	assert(sock->fd == pfd->fd);
	sock->poll_data = NULL;

	if (pfd->revents != 0)
		TRACE2("socket_doio(%d, pfd=<fd=%d, revents=%s)\n", sock->fd, pfd->fd, poll_bit_string(pfd->revents));

	if (pfd->revents & POLLOUT) {
		if ((n = socket_send_queued(sock)) < 0)
			return n;
	}

	if (sock->write_eof == SHUTDOWN_WANTED)
		__socket_try_shutdown(sock);

	if (pfd->revents & (POLLIN | POLLHUP)) {
		unsigned int tailroom = 0;

		if (sock->recv_buf)
			tailroom = buffer_tailroom(sock->recv_buf);
		if (tailroom != 0) {
			n = socket_recv_buffer(sock, sock->recv_buf);
			TRACE2("socket_recv_buffer returns %d\n", n);
			if (n < 0)
				return n;
			if (n == 0)
				sock->read_eof = true;
		}
	}

	return 0;
}
