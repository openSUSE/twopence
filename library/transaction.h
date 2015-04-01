/*
 * Transaction handling routines
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


#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <stdint.h>
#include "socket.h"

typedef struct twopence_transaction twopence_transaction_t;
typedef struct twopence_trans_channel twopence_trans_channel_t;

struct twopence_transaction {
	twopence_transaction_t *next;

	unsigned int		type;
	unsigned int		id;

	/* These are really server side only */
	bool			major_sent;
	bool			minor_sent;

	bool			done;

	bool			(*send)(twopence_transaction_t *);
	bool			(*recv)(twopence_transaction_t *, const twopence_hdr_t *hdr, twopence_buf_t *);

	twopence_protocol_state_t ps;
	twopence_sock_t *	client_sock;

	/* These are really server side only (for command execution) */
	pid_t			pid;
	int			status;

	twopence_trans_channel_t *local_sink;
	twopence_trans_channel_t *local_source;

	struct {
		twopence_status_t	status_ret;
		int			exception;

		twopence_iostream_t *	dot_stream;
		unsigned int		dots_printed;
	} client;
};

extern twopence_transaction_t *	twopence_transaction_new_ex(twopence_sock_t *, unsigned int, const twopence_protocol_state_t *, size_t);
extern twopence_transaction_t *	twopence_transaction_new(twopence_sock_t *client, unsigned int type, const twopence_protocol_state_t *ps);
extern void			twopence_transaction_free(twopence_transaction_t *trans);
extern const char *		twopence_transaction_describe(const twopence_transaction_t *);
extern int			twopence_transaction_send_extract(twopence_transaction_t *, const char *user, const char *remote_name);
extern int			twopence_transaction_send_inject(twopence_transaction_t *, const char *user, const char *remote_name, int remote_mode);
extern twopence_trans_channel_t *twopence_transaction_attach_local_sink(twopence_transaction_t *trans, int fd, unsigned char channel);
extern twopence_trans_channel_t *twopence_transaction_attach_local_source(twopence_transaction_t *trans, int fd, unsigned char channel);
extern twopence_trans_channel_t *twopence_transaction_attach_local_sink_stream(twopence_transaction_t *trans, unsigned char channel, twopence_iostream_t *);
extern twopence_trans_channel_t *twopence_transaction_attach_local_source_stream(twopence_transaction_t *trans, unsigned char channel, twopence_iostream_t *);
extern void			twopence_transaction_close_sink(twopence_transaction_t *trans, unsigned char id);
extern void			twopence_transaction_close_source(twopence_transaction_t *trans, unsigned char id);
extern unsigned int		twopence_transaction_num_channels(const twopence_transaction_t *trans);
extern int			twopence_transaction_fill_poll(twopence_transaction_t *trans, struct pollfd *pfd, unsigned int max);
extern void			twopence_transaction_doio(twopence_transaction_t *trans);
extern void			twopence_transaction_recv_packet(twopence_transaction_t *trans, const twopence_hdr_t *hdr, twopence_buf_t *payload);
extern inline void		twopence_transaction_send_client(twopence_transaction_t *trans, twopence_buf_t *bp);
extern void			twopence_transaction_send_status(twopence_transaction_t *trans, twopence_status_t *st);
extern void			twopence_transaction_fail(twopence_transaction_t *, int);
extern void			twopence_transaction_fail2(twopence_transaction_t *trans, int major, int minor);
extern void			twopence_transaction_send_major(twopence_transaction_t *trans, unsigned int code);
extern void			twopence_transaction_send_minor(twopence_transaction_t *trans, unsigned int code);
extern void			twopence_transaction_send_timeout(twopence_transaction_t *trans);
extern twopence_trans_channel_t *twopence_transaction_find_sink(twopence_transaction_t *trans, unsigned char channel);
extern twopence_trans_channel_t *twopence_transaction_find_source(twopence_transaction_t *trans, unsigned char channel);

/* Client side functions */
extern void			twopence_transaction_set_error(twopence_transaction_t *, int);
extern void			twopence_transaction_set_dot_stream(twopence_transaction_t *, twopence_iostream_t *);

extern bool			twopence_transaction_channel_is_read_eof(const twopence_trans_channel_t *);
extern void			twopence_transaction_channel_set_callback_read_eof(twopence_trans_channel_t *, void (*fn)(twopence_transaction_t *, twopence_trans_channel_t *));
extern void			twopence_transaction_channel_set_callback_write_eof(twopence_trans_channel_t *, void (*fn)(twopence_transaction_t *, twopence_trans_channel_t *));
extern void			twopence_transaction_channel_set_plugged(twopence_trans_channel_t *, bool);
extern int			twopence_transaction_channel_flush(twopence_trans_channel_t *);

#endif /* TRANSACTION_H */
