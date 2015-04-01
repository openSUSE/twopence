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

typedef struct transaction transaction_t;

typedef struct connection connection_t;
typedef struct connection_pool connection_pool_t;

typedef const struct semantics semantics_t;
struct semantics {
	/* Server side operations */
	bool		(*inject_file)(transaction_t *, const char *username, const char *filename, size_t len);
	bool		(*extract_file)(transaction_t *, const char *username, const char *filename);
	bool		(*run_command)(transaction_t *, const char *username, unsigned int timeout, const char *cmdline);
	bool		(*request_quit)(void);
};

#define DEFAULT_COMMAND_TIMEOUT	12	/* seconds */

#define TRANSACTION_MAX_SOURCES	4
struct transaction {
	unsigned int		type;
	unsigned int		id;

	bool			major_sent;
	bool			minor_sent;
	bool			done;

	bool			(*send)(transaction_t *);
	bool			(*recv)(transaction_t *, const twopence_hdr_t *hdr, twopence_buf_t *);

	twopence_protocol_state_t ps;
	twopence_sock_t *	client_sock;

	pid_t			pid;
	int			status;

	twopence_sock_t *	local_sink;

	unsigned int		num_local_sources;
	twopence_sock_t *	local_source[TRANSACTION_MAX_SOURCES];
	twopence_sock_t *	local_source_stderr;
};

extern transaction_t *	transaction_new(twopence_sock_t *client, unsigned int type, const twopence_protocol_state_t *ps);
extern void		transaction_free(transaction_t *trans);
extern twopence_sock_t *	transaction_attach_local_sink(transaction_t *trans, int fd);
extern void		transaction_close_sink(transaction_t *trans);
extern twopence_sock_t *	transaction_attach_local_source(transaction_t *trans, int fd);
extern void		transaction_close_source(transaction_t *trans, unsigned int i);
extern int		transaction_fill_poll(transaction_t *trans, struct pollfd *pfd, unsigned int max);
extern void		transaction_doio(transaction_t *trans);
extern inline void	transaction_send_client(transaction_t *trans, twopence_buf_t *bp);
extern void		transaction_send_status(transaction_t *trans, twopence_status_t *st);
extern void		transaction_queue_stdin(transaction_t *trans, twopence_buf_t *bp);
extern bool		transaction_write_data(transaction_t *trans, twopence_buf_t *payload);
extern bool		transaction_write_eof(transaction_t *trans);
extern int		transaction_process(transaction_t *trans);
extern void		transaction_fail(transaction_t *, int);
extern void		transaction_fail2(transaction_t *trans, int major, int minor);
extern void		transaction_send_major(transaction_t *trans, unsigned int code);
extern void		transaction_send_minor(transaction_t *trans, unsigned int code);
extern void		transaction_send_timeout(transaction_t *trans);

extern connection_t *	connection_new(semantics_t *semantics, twopence_sock_t *client_sock, unsigned int client_id);
extern void		connection_free(connection_t *conn);
extern unsigned int	connection_fill_poll(connection_t *conn, struct pollfd *pfd, unsigned int max);
extern bool		connection_process_packet(connection_t *conn, twopence_buf_t *bp);
extern bool		connection_process(connection_t *conn);

extern connection_pool_t *connection_pool_new(void);
extern void		connection_pool_add_connection(connection_pool_t *pool, connection_t *conn);
extern bool		connection_pool_poll(connection_pool_t *pool);

extern void		server_run(twopence_sock_t *);

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
