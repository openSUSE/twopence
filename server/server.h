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

typedef struct socket socket_t;
typedef struct buffer buffer_t;
typedef struct packet packet_t;
typedef struct queue queue_t;

typedef struct header header_t;
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

/*
 * This should go into some global header file independent of this one.
 */
struct header {
	unsigned char	type;
	unsigned char	pad;
	uint16_t	len;
};
#define TWOPENCE_PROTO_HEADER_SIZE	4
#define TWOPENCE_PROTO_MAX_PACKET	32768
#define TWOPENCE_PROTO_MAX_PAYLOAD	(TWOPENCE_PROTO_MAX_PACKET - TWOPENCE_PROTO_HEADER_SIZE)

#define PROTO_HDR_TYPE_INJECT	'i'
#define PROTO_HDR_TYPE_EXTRACT	'e'
#define PROTO_HDR_TYPE_COMMAND	'c'
#define PROTO_HDR_TYPE_QUIT	'q'
#define PROTO_HDR_TYPE_STDIN	'0'
#define PROTO_HDR_TYPE_STDOUT	'1'
#define PROTO_HDR_TYPE_STDERR	'2'
#define PROTO_HDR_TYPE_DATA	'd'
#define PROTO_HDR_TYPE_EOF	'E'
#define PROTO_HDR_TYPE_INTR	'I'
#define PROTO_HDR_TYPE_MAJOR	'M'
#define PROTO_HDR_TYPE_MINOR	'm'
#define PROTO_HDR_TYPE_TIMEOUT	'T'


struct buffer {
	char *		base;
	unsigned int	head;
	unsigned int	tail;
	unsigned int	size;
};

extern void		buffer_init(buffer_t *bp);
extern void		buffer_init_static(buffer_t *bp, void *data, size_t len);
extern void		buffer_destroy(buffer_t *bp);
extern buffer_t *	buffer_new(size_t max_size);
extern buffer_t *	buffer_clone(buffer_t *bp);
extern void		buffer_free(buffer_t *bp);
extern const void *	buffer_head(const buffer_t *bp);
extern void *		buffer_tail(const buffer_t *bp);
extern unsigned int	buffer_tailroom(const buffer_t *bp);
extern unsigned int	buffer_tailroom_max(const buffer_t *bp);
extern unsigned int	buffer_count(const buffer_t *bp);
extern void *		buffer_pull(buffer_t *bp, unsigned int len);
extern bool		buffer_push(buffer_t *bp, void *data, unsigned int len);
extern bool		buffer_resize(buffer_t *bp, unsigned int want_size);
extern void		buffer_reserve_head(buffer_t *bp, unsigned int len);
extern void *		buffer_reserve_tail(buffer_t *bp, unsigned int len);
extern void		buffer_advance_tail(buffer_t *bp, unsigned int len);
extern void		buffer_advance_head(buffer_t *bp, unsigned int len);
extern void		buffer_truncate(buffer_t *bp, unsigned int len);
extern bool		buffer_append(buffer_t *bp, const void *data, unsigned int len);
extern bool		buffer_puts(buffer_t *bp, const char *s);
extern void		buffer_reset(buffer_t *bp);
extern void		buffer_compact(buffer_t *bp);

extern packet_t *	packet_new(buffer_t *bp);
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
extern int		socket_recv_buffer(socket_t *sock, buffer_t *bp);
extern int		socket_write(socket_t *sock, buffer_t *bp, unsigned int count);
extern int		socket_send_buffer(socket_t *sock, buffer_t *bp);
extern void		socket_queue_xmit(socket_t *sock, buffer_t *bp);
extern void		socket_send_or_queue(socket_t *sock, buffer_t *bp);
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
extern buffer_t *	socket_post_recvbuf_if_needed(socket_t *sock, unsigned int size);
extern void		socket_post_recvbuf(socket_t *sock, buffer_t *bp);
extern buffer_t *	socket_take_recvbuf(socket_t *);
extern buffer_t *	socket_get_recvbuf(socket_t *);


extern void		protocol_build_header(buffer_t *bp, unsigned char type);
extern void		protocol_push_header(buffer_t *bp, unsigned char type);
extern buffer_t *	protocol_command_buffer_new();
extern buffer_t *	protocol_build_eof_packet(void);
extern buffer_t *	protocol_build_uint_packet(unsigned char type, unsigned int value);
extern buffer_t *	protocol_recv_buffer_new(void);
extern bool		protocol_buffer_complete(const buffer_t *bp);
extern const header_t *	protocol_dissect(buffer_t *bp, buffer_t *payload);
extern bool		protocol_dissect_string(buffer_t *bp, char *stringbuf, unsigned int size);
extern bool		protocol_dissect_string_delim(buffer_t *bp, char *stringbuf, unsigned int size, char delimiter);
extern bool		protocol_dissect_uint(buffer_t *bp, unsigned int *retval);

#define TRANSACTION_MAX_SOURCES	4
struct transaction {
	unsigned int		type;
	unsigned int		id;

	bool			major_sent;
	bool			minor_sent;
	bool			done;

	bool			(*send)(transaction_t *);
	bool			(*recv)(transaction_t *, const header_t *hdr, buffer_t *);

	socket_t *		client_sock;

	pid_t			pid;
	int			status;
	unsigned int		byte_count;

	socket_t *		local_sink;

	unsigned int		num_local_sources;
	socket_t *		local_source[TRANSACTION_MAX_SOURCES];
	socket_t *		local_source_stderr;
};

extern transaction_t *	transaction_new(socket_t *client, unsigned int type, unsigned int id);
extern void		transaction_free(transaction_t *trans);
extern socket_t *	transaction_attach_local_sink(transaction_t *trans, int fd);
extern void		transaction_close_sink(transaction_t *trans);
extern socket_t *	transaction_attach_local_source(transaction_t *trans, int fd);
extern void		transaction_close_source(transaction_t *trans, unsigned int i);
extern int		transaction_fill_poll(transaction_t *trans, struct pollfd *pfd, unsigned int max);
extern void		transaction_doio(transaction_t *trans);
extern inline void	transaction_send_client(transaction_t *trans, buffer_t *bp);
extern void		transaction_send_status(transaction_t *trans, twopence_status_t *st);
extern void		transaction_queue_stdin(transaction_t *trans, buffer_t *bp);
extern bool		transaction_write_data(transaction_t *trans, buffer_t *payload);
extern bool		transaction_write_eof(transaction_t *trans);
extern int		transaction_process(transaction_t *trans);
extern void		transaction_fail(transaction_t *, int);
extern void		transaction_fail2(transaction_t *trans, int major, int minor);
extern void		transaction_send_major(transaction_t *trans, unsigned int code);
extern void		transaction_send_minor(transaction_t *trans, unsigned int code);
extern void		transaction_send_timeout(transaction_t *trans);

extern connection_t *	connection_new(semantics_t *semantics, socket_t *client_sock);
extern void		connection_free(connection_t *conn);
extern unsigned int	connection_fill_poll(connection_t *conn, struct pollfd *pfd, unsigned int max);
extern bool		connection_process_packet(connection_t *conn, buffer_t *bp);
extern bool		connection_process(connection_t *conn);

extern connection_pool_t *connection_pool_new(void);
extern void		connection_pool_add_connection(connection_pool_t *pool, connection_t *conn);
extern bool		connection_pool_poll(connection_pool_t *pool);

extern void		server_run(socket_t *);

#define __TRACE(level, fmt...) \
	do { \
		if (server_tracing >= level) \
			twopence_trace(fmt); \
	} while (0)
#define TRACE(fmt...)	__TRACE(1, fmt)
#define TRACE2(fmt...)	__TRACE(2, fmt)

extern unsigned int	server_tracing;

extern void		twopence_trace(const char *fmt, ...);
extern void		twopence_log_error(const char *fmt, ...);

#endif /* SERVER_H */
