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

	socket_t *	client_sock;
	unsigned int	next_id;

	/* We may want to have concurrent transactions later on */
	transaction_t *	current_transaction;
};

connection_t *
connection_new(semantics_t *semantics, socket_t *client_sock)
{
	connection_t *conn;

	conn = calloc(1, sizeof(*conn));
	conn->semantics = semantics;
	conn->client_sock = client_sock;

	return conn;
}

void
connection_close(connection_t *conn)
{
	if (conn->client_sock)
		socket_free(conn->client_sock);
	conn->client_sock = NULL;
}

void
connection_free(connection_t *conn)
{
	connection_close(conn);
	if (conn->current_transaction)
		transaction_free(conn->current_transaction);
	free(conn);
}

unsigned int
connection_fill_poll(connection_t *conn, struct pollfd *pfd, unsigned int max)
{
	unsigned int nfds = 0;
	socket_t *sock;

	sock = conn->client_sock;
	if (sock && socket_is_dead(sock)) {
		TRACE("connection: client socket is dead, closing\n");
		conn->client_sock = NULL;
		socket_free(sock);
		return 0;
	}

	if (conn->current_transaction)
		nfds += transaction_fill_poll(conn->current_transaction, pfd, max);

	if ((sock = conn->client_sock) != NULL) {
		socket_prepare_poll(sock);

		/* Make sure we have a receive buffer posted. */
		socket_post_recvbuf_if_needed(sock, TWOPENCE_PROTO_MAX_PACKET);

		if (socket_xmit_queue_bytes(sock))
			TRACE("socket %d: xmit queue=%u bytes\n", socket_id(sock), socket_xmit_queue_bytes(sock));
		if (nfds < max && socket_fill_poll(sock, pfd + nfds))
			nfds++;
	}

	return nfds;
}

bool
connection_process_packet(connection_t *conn, twopence_buf_t *bp)
{
	const twopence_hdr_t *hdr;
	transaction_t *trans;

	while (bp && twopence_protocol_buffer_complete(bp)) {
		twopence_buf_t payload;

		hdr = twopence_protocol_dissect(bp, &payload);
		if (hdr == NULL) {
			fprintf(stderr, "%s: received invalid packet\n", __func__);
			/* kill the connection? */
			return false;
		}
		TRACE("connection_process_packet type=%c len=%u\n",
				hdr->type, twopence_buf_count(&payload));

		/* Here, we could extract a transaction ID from the header
		 * and locate the right transaction instead of just using
		 * the default one. */
		if ((trans = conn->current_transaction) != NULL) {
			if (trans->done) {
				/* Coming late to the party, uh? */
			} else {
				trans->recv(trans, hdr, &payload);
			}
		} else {
			semantics_t *semantics = conn->semantics;
			transaction_t *trans = NULL;
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
					TRACE("cannot parse packet\n");
					break;
				}

				trans = transaction_new(conn->client_sock, hdr->type, conn->next_id++);
				semantics->inject_file(trans, username, filename, filemode);
				break;

			case TWOPENCE_PROTO_TYPE_EXTRACT:
				if (!twopence_protocol_dissect_string(&payload, username, sizeof(username))
				 || !twopence_protocol_dissect_string(&payload, filename, sizeof(filename)))
					break;

				trans = transaction_new(conn->client_sock, hdr->type, conn->next_id++);
				semantics->extract_file(trans, username, filename);
				break;

			case TWOPENCE_PROTO_TYPE_COMMAND:
				if (!twopence_protocol_dissect_string(&payload, username, sizeof(username))
				 || !twopence_protocol_dissect_uint(&payload, &timeout)
				 || !twopence_protocol_dissect_string_delim(&payload, command, sizeof(command), '\n')
				 || command[0] == '\0')
					break;

				trans = transaction_new(conn->client_sock, hdr->type, conn->next_id++);
				semantics->run_command(trans, username, timeout, command);
				break;

			case TWOPENCE_PROTO_TYPE_QUIT:
				semantics->request_quit();
				break;

			default:
				fprintf(stderr, "Unknown command code '%c' in global context\n", hdr->type);
			}

			if (trans == NULL) {
				TRACE("unable to create transaction, send EPROTO error\n");
				socket_queue_xmit(conn->client_sock,
					 twopence_protocol_build_uint_packet(TWOPENCE_PROTO_TYPE_MAJOR, EPROTO));
			} else {
				conn->current_transaction = trans;
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

	if ((bp = socket_get_recvbuf(conn->client_sock)) == NULL)
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
	transaction_t *trans;
	socket_t *sock;

	if ((sock = conn->client_sock) != NULL) {
		if (socket_doio(sock) < 0) {
			TRACE("I/O error on socket: %m\n");
			exit(1);
		}

		/* See if we have received one or more complete packets */
		if (!connection_process_incoming(conn)) {
			/* Something went wrong */
			exit(1); /* FIXME: shut down this conn forcefully */
		}

		if (socket_is_read_eof(sock)) {
			/* If the client shut down its side of the connection,
			 * we may still have to flush out some data from the
			 * current transaction to the client.
			 * Otherwise, we are really done with this socket and
			 * can close it.
			 */
			if (socket_xmit_queue_bytes(sock) == 0
			 && conn->current_transaction == NULL)
				socket_mark_dead(sock);
		}

		if (socket_is_dead(sock)) {
			connection_close(conn);
		}
	}

	if ((trans = conn->current_transaction) != NULL) {
		transaction_doio(trans);

		if (trans->done) {
			TRACE("current transaction done, free it\n");
			conn->current_transaction = NULL;
			transaction_free(trans);
		} else
		if (sock && socket_is_read_eof(sock)) {
			TRACE("Client closed socket while transaction was in process. Terminate it\n");
			conn->current_transaction = NULL;
			transaction_free(trans);
			connection_close(conn);
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
	connection_t *conn, **connp;
	unsigned int maxfds = 0;
	struct pollfd *pfd;
	unsigned int nfds;
	sigset_t mask;

	if (pool->connections == NULL)
		return false;

	for (conn = pool->connections; conn; conn = conn->next) {
		transaction_t *trans;

		maxfds ++;	/* One socket for the client */
		if ((trans = conn->current_transaction) != NULL)
			maxfds += 1 + TRANSACTION_MAX_SOURCES;
	}

	pfd = alloca(maxfds * sizeof(*pfd));

	connp = &pool->connections;
	nfds = 0;
	while ((conn = *connp) != NULL) {
		unsigned int n;

		n = connection_fill_poll(conn, pfd + nfds, maxfds - nfds);
		if (n == 0) {
			if (conn->client_sock == NULL) {
				*connp = conn->next;
				connection_free(conn);
				continue;
			}
			TRACE("connection doesn't wait for anything?!\n");
		}
		connp = &conn->next;

		nfds += n;
	}

	if (pool->connections == NULL) {
		TRACE("All connections closed\n");
		return false;
	}

	if (nfds == 0) {
		TRACE("No events to wait for?!\n");
	}

	/* Query the current sigprocmask, and allow SIGCHLD while we're polling */
	sigprocmask(SIG_BLOCK, NULL, &mask);
	sigdelset(&mask, SIGCHLD);

	(void) ppoll(pfd, nfds, NULL, &mask);

	for (conn = pool->connections; conn; conn = conn->next)
		connection_doio(conn);

	return !!pool->connections;
}

