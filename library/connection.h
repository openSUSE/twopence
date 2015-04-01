/*
 * Connection management routines
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


#ifndef CONNECTION_H
#define CONNECTION_H

#include <stdint.h>
#include "protocol.h"
#include "socket.h"
#include "transaction.h"

typedef struct twopence_connection twopence_conn_t;
typedef struct twopence_connection_pool twopence_conn_pool_t;

typedef const struct semantics twopence_conn_semantics_t;
struct semantics {
	bool		(*process_request)(twopence_transaction_t *, twopence_buf_t *);
};

extern twopence_conn_t *	twopence_conn_new(twopence_conn_semantics_t *semantics, twopence_sock_t *sock, unsigned int client_id);
extern void			twopence_conn_free(twopence_conn_t *conn);
extern unsigned int		twopence_conn_fill_poll(twopence_conn_t *conn, twopence_pollinfo_t *pinfo);
extern bool			twopence_conn_process_packet(twopence_conn_t *conn, twopence_buf_t *bp);
extern bool			twopence_conn_process(twopence_conn_t *conn);

extern twopence_conn_pool_t *	twopence_conn_pool_new(void);
extern void			twopence_conn_pool_add_connection(twopence_conn_pool_t *pool, twopence_conn_t *conn);
extern bool			twopence_conn_pool_poll(twopence_conn_pool_t *pool);

#endif /* CONNECTION_H */
