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


#ifndef SERVER_H
#define SERVER_H

#include <stdint.h>
#include "twopence.h"
#include "protocol.h"
#include "socket.h"
#include "transaction.h"

typedef struct twopence_connection twopence_conn_t;
typedef struct twopence_connection_pool twopence_conn_pool_t;

typedef const struct semantics twopence_conn_semantics_t;
struct semantics {
	bool		(*process_request)(twopence_transaction_t *, twopence_buf_t *);
};

#define DEFAULT_COMMAND_TIMEOUT	12	/* seconds */

extern twopence_conn_t *	connection_new(twopence_conn_semantics_t *semantics, twopence_sock_t *client_sock, unsigned int client_id);
extern void			connection_free(twopence_conn_t *conn);
extern unsigned int		connection_fill_poll(twopence_conn_t *conn, twopence_pollinfo_t *pinfo);
extern bool			connection_process_packet(twopence_conn_t *conn, twopence_buf_t *bp);
extern bool			connection_process(twopence_conn_t *conn);

extern twopence_conn_pool_t *	connection_pool_new(void);
extern void			connection_pool_add_connection(twopence_conn_pool_t *pool, twopence_conn_t *conn);
extern bool			connection_pool_poll(twopence_conn_pool_t *pool);

extern void			server_run(twopence_sock_t *);

#define AUDIT(fmt, args...) \
	do { \
		if (server_audit) { \
			twopence_trace("%5u: " fmt, server_audit_seq++, ##args); \
		} \
	} while (0)

extern unsigned int	twopence_debug_level;

extern bool		server_audit;
extern unsigned int	server_audit_seq;

#endif /* SERVER_H */
