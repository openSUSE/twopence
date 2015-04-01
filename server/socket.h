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


#ifndef SOCKET_H
#define SOCKET_H

#include <stdint.h>
#include "twopence.h"

typedef struct socket socket_t;
typedef struct packet packet_t;
typedef struct queue queue_t;

extern packet_t *	packet_new(twopence_buf_t *bp);
extern void		packet_free(packet_t *pkt);
extern void		queue_init(queue_t *queue);
extern void		queue_destroy(queue_t *queue);
extern bool		queue_empty(const queue_t *queue);
extern void		queue_append(queue_t *queue, packet_t *pkt);
extern packet_t *	queue_head(const queue_t *queue);
extern bool		queue_full(const queue_t *queue);
extern packet_t *	queue_dequeue(queue_t *queue);

extern socket_t *	socket_new(int fd);
extern socket_t *	socket_new_flags(int fd, int oflags);
extern void		socket_free(socket_t *sock);
extern int		socket_id(const socket_t *sock);
extern int		socket_recv_buffer(socket_t *sock, twopence_buf_t *bp);
extern int		socket_write(socket_t *sock, twopence_buf_t *bp, unsigned int count);
extern int		socket_send_buffer(socket_t *sock, twopence_buf_t *bp);
extern void		socket_queue_xmit(socket_t *sock, twopence_buf_t *bp);
extern int		socket_xmit(socket_t *sock, twopence_buf_t *bp);
extern int		socket_send_queued(socket_t *sock);
extern unsigned int	socket_xmit_queue_bytes(socket_t *sock);
extern bool		socket_xmit_queue_allowed(const socket_t *sock);
extern bool		socket_shutdown_write(socket_t *sock);
extern void		socket_mark_dead(socket_t *sock);
extern bool		socket_is_read_eof(const socket_t *);
extern bool		socket_is_write_eof(const socket_t *);
extern bool		socket_is_dead(socket_t *sock);
extern void		socket_prepare_poll(socket_t *);
extern bool		socket_fill_poll(socket_t *sock, struct pollfd *pfd);
extern int		socket_doio(socket_t *sock);
extern twopence_buf_t *	socket_post_recvbuf_if_needed(socket_t *sock, unsigned int size);
extern void		socket_post_recvbuf(socket_t *sock, twopence_buf_t *bp);
extern twopence_buf_t *	socket_take_recvbuf(socket_t *);
extern twopence_buf_t *	socket_get_recvbuf(socket_t *);

#endif /* SOCKET_H */
