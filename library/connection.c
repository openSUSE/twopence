/*
 * I/O routines for test server.
 *
 * The idea is to avoid interfering with networks test. This enables to test
 * even with all network interfaces are shut down.
 *
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
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h> /* for htons */

#include <errno.h>
#include <signal.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include "connection.h"


typedef struct twopence_conn_list {
	twopence_conn_t *		head;
} twopence_conn_list_t;

/*
 * Connection handling
 */
struct twopence_connection {
	twopence_conn_t *		next;
	twopence_conn_t **		prev;

	twopence_conn_semantics_t *	semantics;

	twopence_sock_t *		client_sock;
	unsigned int			client_id;

	struct {
		unsigned int		send_timeout;
		struct timeval		send_deadline;
		unsigned int		recv_timeout;
		struct timeval		recv_deadline;
	} keepalive;

	/* We may want to have concurrent transactions later on */
	twopence_transaction_list_t	transactions;
	twopence_transaction_list_t	done_transactions;
};

/* When keepalives are enabled, we will shut down the link
 * if there's no traffic for 60 seconds */
#define TWOPENCE_KEEPALIVE_RECV_TIMEOUT	60
#define TWOPENCE_KEEPALIVE_SEND_TIMEOUT	(TWOPENCE_KEEPALIVE_RECV_TIMEOUT / 4)

static void
twopence_conn_list_insert(twopence_conn_list_t *list, twopence_conn_t *conn)
{
	assert(conn->prev == NULL);
	conn->next = list->head;
	if (list->head)
		list->head->prev = &conn->next;
	conn->prev = &list->head;
	list->head = conn;
}

twopence_conn_t *
twopence_conn_new(twopence_conn_semantics_t *semantics, twopence_sock_t *client_sock, unsigned int client_id)
{
	twopence_conn_t *conn;

	conn = twopence_calloc(1, sizeof(*conn));
	conn->semantics = semantics;
	conn->client_sock = client_sock;
	conn->client_id = client_id;

	return conn;
}

void
twopence_conn_set_keepalive(twopence_conn_t *conn, int keepalive)
{
	if (keepalive == 0) {
		twopence_debug("disable keepalives");
		memset(&conn->keepalive, 0, sizeof(conn->keepalive));
		/* twopence_sock_disable_xmit_ts(conn->client_sock); */
	} else {
		if (keepalive < 0)
			keepalive = TWOPENCE_KEEPALIVE_RECV_TIMEOUT;

		if (keepalive < 10)
			keepalive = 10;

		twopence_debug("using keepalives, set idle timeout to %d seconds", keepalive);

		/* Send at least 3 keepalives during timeout interval */
		conn->keepalive.send_timeout = keepalive / 4;
		twopence_sock_enable_xmit_ts(conn->client_sock);

		conn->keepalive.recv_timeout = keepalive;

		twopence_conn_update_send_keepalive(conn);
		twopence_conn_update_recv_keepalive(conn);
	}
}

void
twopence_conn_unlink(twopence_conn_t *conn)
{
	if (conn->prev)
		*(conn->prev) = conn->next;
	if (conn->next)
		conn->next->prev = conn->prev;
	conn->prev = NULL;
	conn->next = NULL;
}

void
twopence_conn_close(twopence_conn_t *conn)
{
	if (conn->client_sock)
		twopence_sock_free(conn->client_sock);
	conn->client_sock = NULL;
}

bool
twopence_conn_is_closed(const twopence_conn_t *conn)
{
	return conn->client_sock == NULL;
}

void
twopence_conn_free(twopence_conn_t *conn)
{
	twopence_transaction_t *trans;

	twopence_conn_unlink(conn);
	twopence_conn_close(conn);
	while ((trans = conn->transactions.head) != NULL) {
		twopence_transaction_unlink(trans);
		twopence_transaction_free(trans);
	}
	free(conn);
}

void
twopence_conn_update_send_keepalive(twopence_conn_t *conn)
{
	if (conn->keepalive.send_timeout != 0
	 && conn->client_sock != NULL
	 && twopence_sock_get_xmit_ts(conn->client_sock, &conn->keepalive.send_deadline))
		conn->keepalive.send_deadline.tv_sec += conn->keepalive.send_timeout;
}

void
twopence_conn_update_recv_keepalive(twopence_conn_t *conn)
{
	if (conn->keepalive.recv_timeout != 0) {
		gettimeofday(&conn->keepalive.recv_deadline, NULL);
		conn->keepalive.recv_deadline.tv_sec += conn->keepalive.recv_timeout;
	}
}

void
twopence_conn_send_keepalive(twopence_conn_t *conn)
{
	twopence_protocol_state_t ps = { .cid = conn->client_id, .xid = 0 };

	twopence_debug("send a keepalive packet");
	twopence_sock_xmit(conn->client_sock,
			twopence_protocol_build_simple_packet_ps(&ps, TWOPENCE_PROTO_TYPE_KEEPALIVE));
	twopence_conn_update_send_keepalive(conn);
}

int
twopence_conn_xmit_packet(twopence_conn_t *conn, twopence_buf_t *bp)
{
	if (conn->client_sock == NULL)
		return TWOPENCE_OPEN_SESSION_ERROR;
	return twopence_sock_xmit(conn->client_sock, bp);
}

twopence_sock_t *
twopence_conn_accept(twopence_conn_t *conn)
{
	if (conn->client_sock == NULL)
		return NULL;
	return twopence_sock_accept(conn->client_sock);
}

unsigned int
twopence_conn_fill_poll(twopence_conn_t *conn, twopence_pollinfo_t *pinfo)
{
	unsigned int current_num_fds = pinfo->num_fds;
	twopence_transaction_t *trans;
	twopence_sock_t *sock;
	int rc;

	sock = conn->client_sock;
	if (sock && twopence_sock_is_dead(sock)) {
		twopence_debug("connection: client socket is dead, closing\n");
		conn->client_sock = NULL;
		twopence_sock_free(sock);
		return 0;
	}

	for (trans = conn->transactions.head; trans; trans = trans->next) {
		if ((rc = twopence_transaction_fill_poll(trans, pinfo)) < 0) {
			/* most likely a timeout */
			twopence_transaction_set_error(trans, rc);
		}
	}

	if ((sock = conn->client_sock) != NULL) {
		twopence_sock_prepare_poll(sock);

		/* Make sure we have a receive buffer posted. */
		twopence_sock_post_recvbuf_if_needed(sock, TWOPENCE_PROTO_MAX_PACKET);

		twopence_sock_fill_poll(sock, pinfo);
	}

	/* Check the keepalive timers */
	if (!twopence_timeout_update(&pinfo->timeout, &conn->keepalive.send_deadline)) {
		/* FIXME: If the socket's send queue is jammed, warn about it */

		/* Transmit a keepalive packet */
		twopence_conn_send_keepalive(conn);

		twopence_timeout_update(&pinfo->timeout, &conn->keepalive.send_deadline);
	}
	if (!twopence_timeout_update(&pinfo->timeout, &conn->keepalive.recv_deadline)) {
		twopence_log_error("link is idle for too long, closing");
		twopence_conn_close(conn);
		return 0;
	}

	/* Return the number of fds we've added */
	return pinfo->num_fds - current_num_fds;
}

/*
 * Add a transaction to the connection
 */
void
twopence_conn_add_transaction(twopence_conn_t *conn, twopence_transaction_t *trans)
{
	twopence_transaction_list_insert(&conn->transactions, trans);
}

void
twopence_conn_add_transaction_done(twopence_conn_t *conn, twopence_transaction_t *trans)
{
	twopence_transaction_list_insert(&conn->done_transactions, trans);
}

twopence_transaction_t *
twopence_conn_reap_transaction(twopence_conn_t *conn, int wait_for_xid)
{
	twopence_transaction_t *rover;

	for (rover = conn->done_transactions.head; rover != NULL; rover = rover->next) {
		if (wait_for_xid == 0 || rover->id == wait_for_xid) {
			twopence_transaction_unlink(rover);
			return rover;
		}
	}
	return NULL;
}

bool
twopence_conn_has_pending_transactions(const twopence_conn_t *conn)
{
	return conn->transactions.head != NULL;
}

static void
twopence_conn_transaction_complete(twopence_conn_t *conn, twopence_transaction_t *trans)
{
	twopence_transaction_unlink(trans);

	/* In the server, we're no longer interested in the transaction once
	 * we're finished with it. On the client side, we do not dispose of it
	 * immediately, but put it on a separate list from which it can be
	 * reaped later. */
	if (conn->semantics && conn->semantics->end_transaction) {
		conn->semantics->end_transaction(conn, trans);
	} else {
		twopence_debug("%s: transaction done, free it", twopence_transaction_describe(trans));
		twopence_transaction_free(trans);
	}
}

void
twopence_conn_cancel_transactions(twopence_conn_t *conn, int error)
{
	twopence_transaction_t *trans;

	if (conn->transactions.head)
		twopence_log_error("remote closed the connection while there were pending transactions");

	twopence_debug("%s()", __func__);
	while ((trans = conn->transactions.head) != NULL) {
		twopence_transaction_set_error(trans, error);
		twopence_conn_transaction_complete(conn, trans);
	}
}

/*
 * Find the transaction corresponding to a given XID.
 */
twopence_transaction_t *
twopence_conn_find_transaction(twopence_conn_t *conn, uint16_t xid)
{
	twopence_transaction_t *trans;

	for (trans = conn->transactions.head; trans; trans = trans->next) {
		if (trans->id == xid)
			return trans;
	}

	return NULL;
}

twopence_transaction_t *
twopence_conn_transaction_new(twopence_conn_t *conn, unsigned int type, const twopence_protocol_state_t *ps)
{
	return twopence_transaction_new(conn->client_sock, type, ps);
}

static bool
twopence_conn_process_request(twopence_conn_t *conn, const twopence_hdr_t *hdr,
		twopence_buf_t *payload, const twopence_protocol_state_t *ps)
{
	twopence_transaction_t *trans = NULL;

	if (!conn->semantics || !conn->semantics->process_request)
		return false;

	trans = twopence_transaction_new(conn->client_sock, hdr->type, ps);
	if (!conn->semantics->process_request(trans, payload)) {
#if 0
		twopence_debug("bad %s packet in incoming request",
			twopence_protocol_packet_type_to_name(hdr->type));
#else
		twopence_debug("bad %c packet in incoming request", hdr->type);
#endif
		twopence_transaction_send_major(trans, EPROTO);
		twopence_transaction_free(trans);
		return false;
	}

	if (!trans->done) {
		twopence_conn_add_transaction(conn, trans);
	} else {
		twopence_transaction_free(trans);
	}
	return true;
}


bool
twopence_conn_process_packet(twopence_conn_t *conn, twopence_buf_t *bp)
{
	const twopence_hdr_t *hdr;
	twopence_transaction_t *trans;

	while (bp && twopence_protocol_buffer_complete(bp)) {
		twopence_protocol_state_t ps;
		twopence_buf_t payload;

		hdr = twopence_protocol_dissect_ps(bp, &payload, &ps);
		if (hdr == NULL) {
			twopence_log_error("%s: received invalid packet\n", __func__);
			/* kill the connection? */
			return false;
		}
		twopence_debug("connection_process_packet cid=%u xid=%u type=%c len=%u\n",
				ps.cid, ps.xid, hdr->type, twopence_buf_count(&payload));

		if (hdr->type == TWOPENCE_PROTO_TYPE_HELLO && ps.cid == 0) {
			/* Process HELLO packet from client */
			ps.cid = conn->client_id;
			twopence_conn_process_request(conn, hdr, &payload, &ps);
			continue;
		}

		if (conn->client_id != ps.cid) {
			twopence_debug("ignoring packet with mismatched client id");
			continue;
		}

		twopence_conn_update_recv_keepalive(conn);
		if (hdr->type == TWOPENCE_PROTO_TYPE_KEEPALIVE) {
			twopence_debug("received keepalive from peer");
			continue;
		}

		trans = twopence_conn_find_transaction(conn, ps.xid);
		if (trans != NULL) {
			twopence_transaction_recv_packet(trans, hdr, &payload);
		} else {
			switch (hdr->type) {
			case TWOPENCE_PROTO_TYPE_DATA:
			case TWOPENCE_PROTO_TYPE_STDIN:
			case TWOPENCE_PROTO_TYPE_EOF:
			case TWOPENCE_PROTO_TYPE_INTR:
				/* Due to bad timing, we may receive the stdin EOF indication from the
				 * client after the process as exited. In this case, the transaction
				 * may no longer exist.
				 * However, we do not want to send a duplicate status response,
				 * so skip the EPROTO thing a few lines down. */
				break;

			default:
				twopence_conn_process_request(conn, hdr, &payload, &ps);
			}
		}
	}

	return true;
}

/*
 * Process incoming packet(s) on the client connection
 */
bool
twopence_conn_process_incoming(twopence_conn_t *conn)
{
	twopence_buf_t *bp;

	if ((bp = twopence_sock_get_recvbuf(conn->client_sock)) == NULL)
		return true;

	while (twopence_protocol_buffer_complete(bp)) {
		if (!twopence_conn_process_packet(conn, bp)) {
			/* Something went wrong */
			return false;
		}
	}

	if (twopence_buf_count(bp) == 0) {
		/* All data has been used. Just reset the buffer */
		twopence_buf_reset(bp);
	} else {
		/* There's an incomplete packet after the end of
		 * the one(s) we just processed.
		 * Make sure we still have ample tailroom
		 * to receive the rest of the packet.
		 */
		if (twopence_buf_tailroom_max(bp) < TWOPENCE_PROTO_MAX_PACKET)
			twopence_buf_compact(bp);
	}

	return true;
}

int
twopence_conn_doio(twopence_conn_t *conn)
{
	twopence_transaction_t *trans, *next;
	twopence_sock_t *sock;

	if ((sock = conn->client_sock) != NULL) {
		if (twopence_sock_doio(sock) < 0) {
			twopence_log_error("I/O error on socket: %m\n");
			twopence_conn_close(conn);
			return TWOPENCE_TRANSPORT_ERROR;
		}

		/* See if we have received one or more complete packets */
		if (!twopence_conn_process_incoming(conn)) {
			/* Something went wrong */
			exit(1); /* FIXME: shut down this conn forcefully */
		}

		if (twopence_sock_is_read_eof(sock)) {
			/* If the client shut down its side of the connection,
			 * we may still have to flush out some data from the
			 * current transaction to the client.
			 * Otherwise, we are really done with this socket and
			 * can close it.
			 */
			if (twopence_sock_xmit_queue_bytes(sock) == 0)
				twopence_sock_mark_dead(sock);
		}

		if (twopence_sock_is_dead(sock)) {
			twopence_conn_cancel_transactions(conn, TWOPENCE_TRANSPORT_ERROR);
			twopence_conn_close(conn);
			return 0;
		}
	}

	for (trans = conn->transactions.head; trans != NULL; trans = next) {
		next = trans->next;

		twopence_transaction_doio(trans);
		if (trans->done) {
			/* Remove the transaction from the list of pending.
			 * Depending on the semantics, this may free the
			 * transaction, or move it to the list of completed
			 * transactions, or doing something yet entirely
			 * different. */
			twopence_conn_transaction_complete(conn, trans);
		}
	}

	/* If anything has been sent down the socket, update our keepalive xmit timer */
	twopence_conn_update_send_keepalive(conn);

	return 0;
}

struct twopence_connection_pool {
	twopence_conn_list_t	connections;

	struct {
		void		(*close_connection)(twopence_conn_t *);
	} callbacks;
};

twopence_conn_pool_t *
twopence_conn_pool_new(void)
{
	twopence_conn_pool_t *pool;

	pool = twopence_calloc(1, sizeof(*pool));
	pool->callbacks.close_connection = twopence_conn_free;
	return pool;
}

void
twopence_conn_pool_set_callback_close_connection(twopence_conn_pool_t *pool, void (*cb)(twopence_conn_t *))
{
	pool->callbacks.close_connection = cb;
}

void
twopence_conn_pool_add_connection(twopence_conn_pool_t *pool, twopence_conn_t *conn)
{
	twopence_conn_list_insert(&pool->connections, conn);
}


bool
twopence_conn_pool_poll(twopence_conn_pool_t *pool)
{
	twopence_pollinfo_t poll_info;
	twopence_conn_t *conn, *next;
	unsigned int maxfds = 0;
	sigset_t mask;

	if (pool->connections.head == NULL)
		return false;

	for (conn = pool->connections.head; conn; conn = conn->next) {
		twopence_transaction_t *trans;

		maxfds ++;	/* One socket for the client */
		for (trans = conn->transactions.head; trans; trans = trans->next)
			maxfds += twopence_transaction_num_channels(trans);
	}

	twopence_pollinfo_init(&poll_info, alloca(maxfds * sizeof(struct pollfd)), maxfds);

	for (conn = pool->connections.head; conn; conn = next) {
		next = conn->next;

		if (twopence_conn_fill_poll(conn, &poll_info) == 0) {
			if (conn->client_sock == NULL) {
				twopence_conn_unlink(conn);

				if (pool->callbacks.close_connection)
					pool->callbacks.close_connection(conn);
				continue;
			}
			twopence_debug("connection doesn't wait for anything?!\n");
		}
	}

	if (pool->connections.head == NULL) {
		twopence_debug("All connections closed\n");
		return false;
	}

	/* Query the current sigprocmask, and allow SIGCHLD while we're polling */
	sigprocmask(SIG_BLOCK, NULL, &mask);
	sigdelset(&mask, SIGCHLD);

	(void) twopence_pollinfo_ppoll(&poll_info, &mask);

	for (conn = pool->connections.head; conn; conn = conn->next) {
		int rc;

		/* This is really just for accepting incoming connections on a listening
		 * socket. */
		if (conn->semantics && conn->semantics->doio) {
			rc = conn->semantics->doio(pool, conn);
		} else {
			rc = twopence_conn_doio(conn);
		}

		if (rc < 0) {
			twopence_log_error("%s: error when processing IO, closing connection: %s", __func__, twopence_strerror(rc));
			twopence_conn_close(conn);
		}
	}

	return !!pool->connections.head;
}

