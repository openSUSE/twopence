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
#include <sys/socket.h>
#include <sys/un.h>

#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "twopence.h"
#include "protocol.h"
#include "socket.h"


typedef struct twopence_packet twopence_packet_t;
typedef struct twopence_queue twopence_queue_t;

struct twopence_queue {
	unsigned int		bytes;
	unsigned int		max_bytes;

	twopence_packet_t *	head;
	twopence_packet_t **	tail;
};

struct twopence_socket {
	int			fd;

	unsigned int		bytes_sent;

	twopence_queue_t	xmit_queue;
	twopence_buf_t *	recv_buf;

	bool			read_eof;
	unsigned char		write_eof;

	struct pollfd *		poll_data;
};

struct twopence_packet {
	twopence_packet_t *	next;

	unsigned int		bytes;
	twopence_buf_t *	buffer;
};

#define SHUTDOWN_WANTED		1
#define SHUTDOWN_SENT		2

static twopence_packet_t *
twopence_packet_new(twopence_buf_t *bp)
{
	twopence_packet_t *pkt;

	pkt = calloc(1, sizeof(*pkt));
	pkt->buffer = bp;
	pkt->bytes = twopence_buf_count(bp);
	return pkt;
}

static void
twopence_packet_free(twopence_packet_t *pkt)
{
	if (pkt->buffer)
		twopence_buf_free(pkt->buffer);
	free(pkt);
}

static void
twopence_queue_init(twopence_queue_t *queue)
{
	queue->head = NULL;
	queue->tail = &queue->head;
	queue->max_bytes = 16 * 65536;
}

static void
twopence_queue_destroy(twopence_queue_t *queue)
{
	twopence_packet_t *pkt;

	while ((pkt = queue->head) != NULL) {
		queue->head = pkt->next;
		twopence_packet_free(pkt);
	}
	queue->tail = &queue->head;
}

static bool
twopence_queue_empty(const twopence_queue_t *queue)
{
	return queue->head == NULL;
}

static void
twopence_queue_append(twopence_queue_t *queue, twopence_packet_t *pkt)
{
	*queue->tail = pkt;
	queue->tail = &pkt->next;
	queue->bytes += pkt->bytes;
}

static twopence_packet_t *
twopence_queue_head(const twopence_queue_t *queue)
{
	return queue->head;
}

static bool
twopence_queue_full(const twopence_queue_t *queue)
{
	return queue->max_bytes == 0 || queue->bytes >= queue->max_bytes;
}

static twopence_packet_t *
twopence_queue_dequeue(twopence_queue_t *queue)
{
	twopence_packet_t *pkt;

	if ((pkt = queue->head) != NULL) {
		assert(pkt->bytes <= queue->bytes);
		queue->bytes -= pkt->bytes;

		queue->head = pkt->next;
		if (queue->head == NULL)
			queue->tail = &queue->head;
	}
	return pkt;
}

static twopence_sock_t *
__twopence_socket_new(int fd, int oflags)
{
	twopence_sock_t *sock;
	int f;

	sock = calloc(1, sizeof(*sock));
	sock->fd = fd;

	/* Set flags (usually for nonblocking IO) */
	if ((f = fcntl(fd, F_GETFL)) < 0
	 || fcntl(fd, F_SETFL, f | oflags) < 0) {
		twopence_log_error("socket_new: trouble setting socket to nonblocking I/O: %m\n");
		/* Continue anyway */
	}

	twopence_queue_init(&sock->xmit_queue);
	return sock;
}

twopence_sock_t *
twopence_sock_new(int fd)
{
	return __twopence_socket_new(fd, O_NONBLOCK);
}

twopence_sock_t *
twopence_sock_new_flags(int fd, int oflags)
{
	twopence_sock_t *sock;

	sock = __twopence_socket_new(fd, oflags & ~O_ACCMODE);
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
twopence_sock_free(twopence_sock_t *sock)
{
	twopence_debug("%s(%d)\n", __func__, sock->fd);
	if (sock->fd >= 0)
		close(sock->fd);

	twopence_queue_destroy(&sock->xmit_queue);
	if (sock->recv_buf)
		twopence_buf_free(sock->recv_buf);
	free(sock);
}

int
twopence_sock_id(const twopence_sock_t *sock)
{
	return sock->fd;
}

int
twopence_sock_recv_buffer(twopence_sock_t *sock, twopence_buf_t *bp)
{
	unsigned int count;
	int n;

	count = twopence_buf_tailroom(bp);
	if (count == 0) {
		twopence_debug("%s: no tailroom in buffer", __func__);
		errno = ENOBUFS;
		return -1;
	}

#if 0
	/* Testing: simulate serial pipe behavior - large packets get chopped
	 * up into 4k chunks */
	if (count > 4096)
		count = 4096;
#endif

	n = read(sock->fd, twopence_buf_tail(bp), count);
	if (n > 0)
		twopence_buf_advance_tail(bp, n);
	else if (n < 0)
		twopence_debug("%s: recv() returns error: %m", __func__);
	return n;
}

twopence_buf_t *
twopence_sock_take_recvbuf(twopence_sock_t *sock)
{
	twopence_buf_t *bp;

	if ((bp = sock->recv_buf) == NULL
	 || twopence_buf_count(bp) == 0)
		return NULL;

	sock->recv_buf = NULL;
	return bp;
}

twopence_buf_t *
twopence_sock_get_recvbuf(twopence_sock_t *sock)
{
	return sock->recv_buf;
}

void
twopence_sock_post_recvbuf(twopence_sock_t *sock, twopence_buf_t *bp)
{
	if (sock->recv_buf != NULL) {
		assert(twopence_buf_count(sock->recv_buf) == 0);
		twopence_buf_free(sock->recv_buf);
	}
	sock->recv_buf = bp;
}

twopence_buf_t *
twopence_sock_post_recvbuf_if_needed(twopence_sock_t *sock, unsigned int size)
{
	/* If the socket is at EOF, or if we already have posted a
	 * receive buffer, there's no need to post a new one.
	 * Return NULL.
	 */
	if (sock->read_eof || sock->recv_buf != NULL)
		return NULL;

	sock->recv_buf = twopence_buf_new(size);
	return sock->recv_buf;
}

int
twopence_sock_write(twopence_sock_t *sock, twopence_buf_t *bp, unsigned int count)
{
	int n;

	if (count == 0)
		return 0;

	if (twopence_buf_count(bp) < count)
		count = twopence_buf_count(bp);

	n = write(sock->fd, twopence_buf_head(bp), count);
	if (n > 0)
		sock->bytes_sent += n;
	return n;
}

int
twopence_sock_send_buffer(twopence_sock_t *sock, twopence_buf_t *bp)
{
	int n;

	n = twopence_sock_write(sock, bp, twopence_buf_count(bp));
	if (n > 0) {
		twopence_debug2("%s(%d): wrote %u bytes\n", __func__, sock->fd, n);
		twopence_buf_advance_head(bp, n);
	}
	return n;
}

/*
 * These flags indicate the desired degree of "sync" behavior.
 *  none:	 fully async, just append to queue
 *  trytowrite:	 opportunistic: write data directly if we can, otherwise queue
 *  synchronous: fully synchronous, write out the buffer before returning
 *
 * Independent of the above
 *  unshare:     create a clone of the buffer object before queuing it
 */
#define TWOPENCE_SOCK_XMIT_TRYTOWRITE	0x0001
#define TWOPENCE_SOCK_XMIT_SYNCHRONOUS	0x0002
#define TWOPENCE_SOCK_XMIT_CLONEBUF	0x0004

static int
__socket_queue_xmit(twopence_sock_t *sock, twopence_buf_t *bp, int flags)
{
	int n = 0, f;

	f = fcntl(sock->fd, F_GETFL);
	if (flags & TWOPENCE_SOCK_XMIT_SYNCHRONOUS)
		fcntl(sock->fd, F_SETFL, f & ~O_NONBLOCK);

	if (sock->write_eof) {
		twopence_log_error("%s: attempt to queue data after write shutdown", __func__);
		goto out_drop_buffer;
	}

	if (flags & TWOPENCE_SOCK_XMIT_SYNCHRONOUS) {
		/* Flush out all queued packets first */
		while (twopence_queue_head(&sock->xmit_queue) != NULL) {
			n = twopence_sock_send_queued(sock);
			if (n < 0)
				goto out_drop_buffer;
		}
	}

	/* If nothing is queued to the socket, we might as well try to
	 * send this data directly. */
	if (twopence_queue_empty(&sock->xmit_queue)) {
		if (flags & TWOPENCE_SOCK_XMIT_SYNCHRONOUS) {
			/* fully synchronous */
			while (twopence_buf_count(bp) != 0) {
				n = twopence_sock_send_buffer(sock, bp);
				if (n < 0)
					goto out_drop_buffer;
			}
		} else
		if (flags & TWOPENCE_SOCK_XMIT_TRYTOWRITE) {
			/* opportunistic - write some */
			(void) twopence_sock_send_buffer(sock, bp);
		}
	}

	/* If there's data left in this buffer, queue it to the socket */
	if (twopence_buf_count(bp) != 0) {
		if (flags & TWOPENCE_SOCK_XMIT_CLONEBUF)
			bp = twopence_buf_clone(bp);
		twopence_queue_append(&sock->xmit_queue, twopence_packet_new(bp));
		goto out;
	}

out_drop_buffer:
	if (!(flags & TWOPENCE_SOCK_XMIT_CLONEBUF))
		twopence_buf_free(bp);

out:
	fcntl(sock->fd, F_SETFL, f);
	return n;
}

void
twopence_sock_queue_xmit(twopence_sock_t *sock, twopence_buf_t *bp)
{
	__socket_queue_xmit(sock, bp, TWOPENCE_SOCK_XMIT_TRYTOWRITE);
}

int
twopence_sock_xmit_shared(twopence_sock_t *sock, twopence_buf_t *bp)
{
	return __socket_queue_xmit(sock, bp, TWOPENCE_SOCK_XMIT_TRYTOWRITE | TWOPENCE_SOCK_XMIT_CLONEBUF);
}

int
twopence_sock_xmit(twopence_sock_t *sock, twopence_buf_t *bp)
{
	return __socket_queue_xmit(sock, bp, TWOPENCE_SOCK_XMIT_SYNCHRONOUS);
}

int
twopence_sock_send_queued(twopence_sock_t *sock)
{
	twopence_packet_t *pkt;
	int n;

	if ((pkt = twopence_queue_head(&sock->xmit_queue)) == NULL)
		return 0;

	n = twopence_sock_send_buffer(sock, pkt->buffer);
	if (twopence_buf_count(pkt->buffer) == 0) {
		/* Sent the complete buffer */
		twopence_queue_dequeue(&sock->xmit_queue);
		twopence_packet_free(pkt);
	}

	return n;
}

unsigned int
twopence_sock_xmit_queue_bytes(twopence_sock_t *sock)
{
	return sock->xmit_queue.bytes;
}

bool
twopence_sock_xmit_queue_allowed(const twopence_sock_t *sock)
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

	if (twopence_queue_full(&sock->xmit_queue))
		return false;

	return true;
}

static bool
__socket_try_shutdown(twopence_sock_t *sock)
{
	if (twopence_queue_empty(&sock->xmit_queue)) {
		shutdown(sock->fd, SHUT_WR);
		sock->write_eof = SHUTDOWN_SENT;
		return true;
	}
	return false;
}

bool
twopence_sock_shutdown_write(twopence_sock_t *sock)
{
	if (sock->write_eof)
		return true;

	sock->write_eof = SHUTDOWN_WANTED;
	__socket_try_shutdown(sock);
	return true;
}

void
twopence_sock_mark_dead(twopence_sock_t *sock)
{
	sock->read_eof = true;
	sock->write_eof = SHUTDOWN_SENT;
}

bool
twopence_sock_is_read_eof(const twopence_sock_t *sock)
{
	return sock->read_eof;
}

bool
twopence_sock_is_write_eof(const twopence_sock_t *sock)
{
	return sock->write_eof == SHUTDOWN_SENT;
}

bool
twopence_sock_is_dead(twopence_sock_t *sock)
{
	return sock->read_eof && sock->write_eof == SHUTDOWN_SENT;
}

const char *
twopence_sock_state_desc(const twopence_sock_t *sock)
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
twopence_sock_queue_desc(const twopence_sock_t *sock)
{
	static char buffer[60];
	unsigned int recv_bytes = sock->recv_buf? twopence_buf_count(sock->recv_buf) : 0;
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
twopence_sock_prepare_poll(twopence_sock_t *sock)
{
	sock->poll_data = NULL;
}

bool
twopence_sock_fill_poll(twopence_sock_t *sock, struct pollfd *pfd)
{
	sock->poll_data = NULL;

	memset(pfd, 0, sizeof(*pfd));
	if (sock->fd < 0)
		return false;

	if (sock->write_eof != SHUTDOWN_SENT) {
		if (!twopence_queue_empty(&sock->xmit_queue))
			pfd->events |= POLLOUT;
	}
	if (!sock->read_eof) {
		if (sock->recv_buf != NULL && twopence_buf_tailroom_max(sock->recv_buf) != 0)
			pfd->events |= POLLIN;
	}

	if (pfd->events == 0)
		return false;

	twopence_debug2("%s(fd=%d, %s%s): events=%s\n", __func__, sock->fd, twopence_sock_state_desc(sock), twopence_sock_queue_desc(sock), poll_bit_string(pfd->events));
	sock->poll_data = pfd;
	pfd->fd = sock->fd;
	return true;
}

int
twopence_sock_doio(twopence_sock_t *sock)
{
	struct pollfd *pfd;
	int n;

	if ((pfd = sock->poll_data) == NULL)
		return 0;
	assert(sock->fd == pfd->fd);
	sock->poll_data = NULL;

	if (pfd->revents != 0)
		twopence_debug2("twopence_sock_doio(%d, pfd=<fd=%d, revents=%s)\n", sock->fd, pfd->fd, poll_bit_string(pfd->revents));

	if (pfd->revents & POLLOUT) {
		if ((n = twopence_sock_send_queued(sock)) < 0)
			return n;
	}

	if (sock->write_eof == SHUTDOWN_WANTED)
		__socket_try_shutdown(sock);

	if (pfd->revents & (POLLIN | POLLHUP)) {
		unsigned int tailroom = 0;

		if (sock->recv_buf)
			tailroom = twopence_buf_tailroom(sock->recv_buf);
		if (tailroom != 0) {
			n = twopence_sock_recv_buffer(sock, sock->recv_buf);
			twopence_debug2("socket_recv_buffer returns %d\n", n);
			if (n < 0)
				return n;
			if (n == 0)
				sock->read_eof = true;
		}
	}

	return 0;
}