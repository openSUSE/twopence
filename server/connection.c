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


/*
 * Connection handling
 */
struct connection {
	connection_t *	next;

	semantics_t *	semantics;

	twopence_sock_t *client_sock;
	unsigned int	client_id;
	unsigned int	next_id;

	/* We may want to have concurrent transactions later on */
	twopence_transaction_t *	transactions;
};

connection_t *
connection_new(semantics_t *semantics, twopence_sock_t *client_sock, unsigned int client_id)
{
	connection_t *conn;

	conn = calloc(1, sizeof(*conn));
	conn->semantics = semantics;
	conn->client_sock = client_sock;
	conn->client_id = client_id;

	return conn;
}

void
connection_close(connection_t *conn)
{
	if (conn->client_sock)
		twopence_sock_free(conn->client_sock);
	conn->client_sock = NULL;
}

void
connection_free(connection_t *conn)
{
	twopence_transaction_t *trans;

	connection_close(conn);
	while ((trans = conn->transactions) != NULL) {
		conn->transactions = trans->next;
		twopence_transaction_free(trans);
	}
	free(conn);
}

unsigned int
connection_fill_poll(connection_t *conn, twopence_pollinfo_t *pinfo)
{
	unsigned int current_num_fds = pinfo->num_fds;
	twopence_transaction_t *trans;
	twopence_sock_t *sock;

	sock = conn->client_sock;
	if (sock && twopence_sock_is_dead(sock)) {
		twopence_debug("connection: client socket is dead, closing\n");
		conn->client_sock = NULL;
		twopence_sock_free(sock);
		return 0;
	}

	for (trans = conn->transactions; trans; trans = trans->next)
		twopence_transaction_fill_poll(trans, pinfo);

	if ((sock = conn->client_sock) != NULL) {
		twopence_sock_prepare_poll(sock);

		/* Make sure we have a receive buffer posted. */
		twopence_sock_post_recvbuf_if_needed(sock, TWOPENCE_PROTO_MAX_PACKET);

		twopence_sock_fill_poll(sock, pinfo);
	}

	/* Return the number of fds we've added */
	return pinfo->num_fds - current_num_fds;
}

/*
 * Find the transaction corresponding to a given XID.
 * Trivial for now, as we do not support concurrent transactions yet.
 */
twopence_transaction_t *
connection_find_transaction(connection_t *conn, uint16_t xid)
{
	twopence_transaction_t *trans;

	for (trans = conn->transactions; trans; trans = trans->next) {
		if (trans->id == xid)
			return trans;
	}

	return NULL;
}

bool
connection_process_packet(connection_t *conn, twopence_buf_t *bp)
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

		if (hdr->type == TWOPENCE_PROTO_TYPE_HELLO) {
			/* HELLO packet. Respond with the ID we assigned to the client */
			twopence_sock_queue_xmit(conn->client_sock,
				twopence_protocol_build_hello_packet(conn->client_id));
			continue;
		}

		if (conn->client_id != ps.cid) {
			twopence_debug("ignoring packet with mismatched client id");
			continue;
		}

		/* Here, we could extract a transaction ID from the header
		 * and locate the right transaction instead of just using
		 * the default one. */
		trans = connection_find_transaction(conn, ps.xid);
		if (trans != NULL) {
			twopence_transaction_recv_packet(trans, hdr, &payload);
		} else {
			semantics_t *semantics = conn->semantics;
			twopence_transaction_t *trans = NULL;
			char username[128];
			char filename[PATH_MAX];
			char command[2048];
			unsigned int filemode = 0;
			unsigned int timeout = 0;

			switch (hdr->type) {
			case TWOPENCE_PROTO_TYPE_INJECT:
				if (!twopence_protocol_dissect_string(&payload, username, sizeof(username))
				 || !twopence_protocol_dissect_uint(&payload, &filemode)
				 || !twopence_protocol_dissect_string(&payload, filename, sizeof(filename))) {
					twopence_debug("cannot parse packet\n");
					break;
				}

				trans = twopence_transaction_new(conn->client_sock, hdr->type, &ps);
				semantics->inject_file(trans, username, filename, filemode);
				break;

			case TWOPENCE_PROTO_TYPE_EXTRACT:
				if (!twopence_protocol_dissect_string(&payload, username, sizeof(username))
				 || !twopence_protocol_dissect_string(&payload, filename, sizeof(filename)))
					break;

				trans = twopence_transaction_new(conn->client_sock, hdr->type, &ps);
				semantics->extract_file(trans, username, filename);
				break;

			case TWOPENCE_PROTO_TYPE_COMMAND:
				if (!twopence_protocol_dissect_string(&payload, username, sizeof(username))
				 || !twopence_protocol_dissect_uint(&payload, &timeout)
				 || !twopence_protocol_dissect_string_delim(&payload, command, sizeof(command), '\n')
				 || command[0] == '\0') {
					twopence_debug("Failed to parse COMMAND packet\n");
					break;
				}

				trans = twopence_transaction_new(conn->client_sock, hdr->type, &ps);
				semantics->run_command(trans, username, timeout, command);
				break;

			case TWOPENCE_PROTO_TYPE_QUIT:
				semantics->request_quit();
				continue;

			case TWOPENCE_PROTO_TYPE_DATA:
			case TWOPENCE_PROTO_TYPE_STDIN:
			case TWOPENCE_PROTO_TYPE_EOF:
				/* Due to bad timing, we may receive the stdin EOF indication from the
				 * client after the process as exited. In this case, the transaction
				 * may no longer exist.
				 * However, we do not want to send a duplicate status response,
				 * so skip the EPROTO thing a few lines down. */
				continue;

			default:
				twopence_debug("Unknown command code '%c' in global context\n", hdr->type);
			}

			if (trans == NULL) {
				twopence_debug("unable to create transaction, send EPROTO error\n");
				twopence_sock_queue_xmit(conn->client_sock,
					 twopence_protocol_build_uint_packet_ps(&ps, TWOPENCE_PROTO_TYPE_MAJOR, EPROTO));
			} else {
				trans->next = conn->transactions;
				conn->transactions = trans;
			}
		}
	}

	return true;
}

/*
 * Process incoming packet(s) on the client connection
 */
bool
connection_process_incoming(connection_t *conn)
{
	twopence_buf_t *bp;

	if ((bp = twopence_sock_get_recvbuf(conn->client_sock)) == NULL)
		return true;

	while (twopence_protocol_buffer_complete(bp)) {
		if (!connection_process_packet(conn, bp)) {
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

void
connection_doio(connection_t *conn)
{
	twopence_transaction_t **pos, *trans;
	twopence_sock_t *sock;

	if ((sock = conn->client_sock) != NULL) {
		if (twopence_sock_doio(sock) < 0) {
			twopence_debug("I/O error on socket: %m\n");
			connection_close(conn);
			return;
		}

		/* See if we have received one or more complete packets */
		if (!connection_process_incoming(conn)) {
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
			if (twopence_sock_xmit_queue_bytes(sock) == 0
			 && conn->transactions == NULL)
				twopence_sock_mark_dead(sock);
		}

		if (twopence_sock_is_dead(sock)) {
			connection_close(conn);
			return;
		}
	}

	for (pos = &conn->transactions; (trans = *pos) != NULL; ) {
		twopence_transaction_doio(trans);

		if (trans->done) {
			twopence_debug("%s: transaction done, free it", twopence_transaction_describe(trans));
			*pos = trans->next;
			twopence_transaction_free(trans);
		} else {
			pos = &trans->next;
		}
	}
}

struct connection_pool {
	connection_t *		connections;
};

connection_pool_t *
connection_pool_new(void)
{
	connection_pool_t *pool;

	pool = calloc(1, sizeof(*pool));
	return pool;
}

void
connection_pool_add_connection(connection_pool_t *pool, connection_t *conn)
{
	conn->next = pool->connections;
	pool->connections = conn;
}


bool
connection_pool_poll(connection_pool_t *pool)
{
	twopence_pollinfo_t poll_info;
	connection_t *conn, **connp;
	unsigned int maxfds = 0;
	sigset_t mask;

	if (pool->connections == NULL)
		return false;

	for (conn = pool->connections; conn; conn = conn->next) {
		twopence_transaction_t *trans;

		maxfds ++;	/* One socket for the client */
		for (trans = conn->transactions; trans; trans = trans->next)
			maxfds += twopence_transaction_num_channels(trans);
	}

	twopence_pollinfo_init(&poll_info, alloca(maxfds * sizeof(struct pollfd)), maxfds);

	connp = &pool->connections;
	while ((conn = *connp) != NULL) {
		if (connection_fill_poll(conn, &poll_info) == 0) {
			if (conn->client_sock == NULL) {
				*connp = conn->next;
				connection_free(conn);
				continue;
			}
			twopence_debug("connection doesn't wait for anything?!\n");
		}
		connp = &conn->next;
	}

	if (pool->connections == NULL) {
		twopence_debug("All connections closed\n");
		return false;
	}

	if (poll_info.num_fds == 0) {
		twopence_debug("No events to wait for?!\n");
	}

	/* Query the current sigprocmask, and allow SIGCHLD while we're polling */
	sigprocmask(SIG_BLOCK, NULL, &mask);
	sigdelset(&mask, SIGCHLD);

	(void) twopence_pollinfo_ppoll(&poll_info, &mask);

	for (conn = pool->connections; conn; conn = conn->next)
		connection_doio(conn);

	return !!pool->connections;
}

