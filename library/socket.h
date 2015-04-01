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

typedef struct twopence_socket twopence_sock_t;

extern twopence_sock_t *twopence_sock_new(int fd);
extern twopence_sock_t *twopence_sock_new_flags(int fd, int oflags);
extern void		twopence_sock_free(twopence_sock_t *sock);
extern int		twopence_sock_id(const twopence_sock_t *sock);
extern int		socket_recv_buffer(twopence_sock_t *sock, twopence_buf_t *bp);
extern int		twopence_sock_write(twopence_sock_t *sock, twopence_buf_t *bp, unsigned int count);
extern int		socket_send_buffer(twopence_sock_t *sock, twopence_buf_t *bp);
extern void		socket_queue_xmit(twopence_sock_t *sock, twopence_buf_t *bp);
extern int		twopence_sock_xmit(twopence_sock_t *sock, twopence_buf_t *bp);
extern int		socket_send_queued(twopence_sock_t *sock);
extern unsigned int	socket_xmit_queue_bytes(twopence_sock_t *sock);
extern bool		socket_xmit_queue_allowed(const twopence_sock_t *sock);
extern bool		socket_shutdown_write(twopence_sock_t *sock);
extern void		socket_mark_dead(twopence_sock_t *sock);
extern bool		socket_is_read_eof(const twopence_sock_t *);
extern bool		socket_is_write_eof(const twopence_sock_t *);
extern bool		socket_is_dead(twopence_sock_t *sock);
extern void		socket_prepare_poll(twopence_sock_t *);
extern bool		socket_fill_poll(twopence_sock_t *sock, struct pollfd *pfd);
extern int		twopence_sock_doio(twopence_sock_t *sock);
extern twopence_buf_t *	socket_post_recvbuf_if_needed(twopence_sock_t *sock, unsigned int size);
extern void		socket_post_recvbuf(twopence_sock_t *sock, twopence_buf_t *bp);
extern twopence_buf_t *	socket_take_recvbuf(twopence_sock_t *);
extern twopence_buf_t *	socket_get_recvbuf(twopence_sock_t *);

#endif /* SOCKET_H */
