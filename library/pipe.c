/*
Test executor, virtio and serial plugins
(the ones that use a custom protocol to communicate with the remote host).


Copyright (C) 2014-2015 SUSE

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 2.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include <sys/stat.h>
#include <sys/poll.h>
#include <stdio.h>                     // For snprintf() parsing facility. Most I/O is low-level and unbuffered.
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include "twopence.h"
#include "protocol.h"
#include "transaction.h"
#include "pipe.h"

#define BUFFER_SIZE 32768              // Size in bytes of the work buffer for receiving data from the remote
#define LINE_TIMEOUT 60000             // Maximum silence on the line in milliseconds
#define COMMAND_BUFFER_SIZE 8192       // Size in bytes of the work buffer for sending data to the remote


static int	__twopence_pipe_handshake(struct twopence_pipe_target *handle);

/*
 * Class initialization
 */
void
twopence_pipe_target_init(struct twopence_pipe_target *target, int plugin_type, const struct twopence_plugin *plugin_ops,
			const struct twopence_pipe_ops *link_ops)
{
  memset(target, 0, sizeof(*target));

  target->base.plugin_type = plugin_type;
  target->base.ops = plugin_ops;
  target->link_timeout = LINE_TIMEOUT;
  target->link_ops = link_ops;
  target->link_sock = NULL;
}

///////////////////////////// Lower layer ///////////////////////////////////////

// Output a "stdout" character through one of the available methods
//
// Returns 0 if everything went fine, -1 otherwise
static int
__twopence_pipe_output(struct twopence_pipe_target *handle, char c)
{
  return twopence_target_putc(&handle->base, TWOPENCE_STDOUT, c);
}

// Output a "stderr" character through one of the available methods
//
// Returns 0 if everything went fine, -1 otherwise
static inline int
__twopence_pipe_error(struct twopence_pipe_target *handle, char c)
{
  return twopence_target_putc(&handle->base, TWOPENCE_STDERR, c);
}

static inline int
__twopence_pipe_write_stream(twopence_iostream_t *stream, twopence_buf_t *bp)
{
  if (stream == NULL)
    return 0;

  return twopence_iostream_write(stream, twopence_buf_head(bp), twopence_buf_count(bp));
}

static inline int
__twopence_pipe_write(struct twopence_pipe_target *handle, twopence_iofd_t dst, twopence_buf_t *bp)
{
  twopence_iostream_t *stream;

  stream = twopence_target_stream(&handle->base, dst);
  return __twopence_pipe_write_stream(stream, bp);
}

// Check for invalid usernames
static bool
_twopence_invalid_username(const char *username)
{
  const char *p;

  for (p = username; *p; p++)
  {
    if ('0' <= *p && *p <= '9') continue;
    if ('A' <= *p && *p <= 'Z') continue;
    if ('a' <= *p && *p <= 'z') continue;
    if (*p == '_') continue;
    return true;
  }

  return false;
}

/*
 * Wrap the link functions
 */
static int
__twopence_pipe_open_link(struct twopence_pipe_target *handle)
{
  if (handle->link_sock == NULL) {
    /* The socket we are given should be set up for blocking I/O */
    handle->link_sock = handle->link_ops->open(handle);
    if (handle->link_sock == NULL)
      return TWOPENCE_OPEN_SESSION_ERROR;

    if (__twopence_pipe_handshake(handle) < 0) {
      twopence_sock_free(handle->link_sock);
      handle->link_sock = NULL;
      return TWOPENCE_OPEN_SESSION_ERROR;
    }
  }

  return 0;
}

/*
 * Transmit a single buffer.
 * This is synchronous for now
 */
static int
__twopence_pipe_send(struct twopence_pipe_target *handle, twopence_buf_t *bp)
{
  int count = twopence_buf_count(bp);
  int rc = 0;

  if (handle->link_sock == NULL)
    return TWOPENCE_PROTOCOL_ERROR; /* SESSION_ERROR? */

  /* FIXME: heed the link timeout */

  /* Transmit and free the buffer */
  rc = twopence_sock_xmit(handle->link_sock, bp);
  if (rc < 0)
    return rc;

  return count;
}

static int
__twopence_pipe_send_eof(struct twopence_pipe_target *handle, twopence_protocol_state_t *ps)
{
  return __twopence_pipe_send(handle, twopence_protocol_build_eof_packet(ps));
}

/*
 * Read a chunk (normally called a packet or frame) from the link
 */
static twopence_buf_t *
__twopence_pipe_read_packet(struct twopence_pipe_target *handle)
{
  twopence_sock_t *sock;
  twopence_buf_t *bp;

  if ((sock = handle->link_sock) == NULL)
    return NULL;
  bp = twopence_sock_get_recvbuf(sock);

  /* Receive more data from the link until we have at least one
   * complete packet.
   * Note: we may receive more data than that.
   */
  while (!twopence_protocol_buffer_complete(bp)) {
    int count;

    /* FIXME: heed the link timeout */
    count = twopence_sock_recv_buffer(sock, bp);
    if (count == 0) {
      twopence_log_error("unexpected EOF on link");
      return NULL;
    }
    if (count < 0) {
      twopence_log_error("receive error on link: %m");
      return NULL;
    }
  }

  return bp;
}

/*
 * Perform the initial exchange of HELLO packets
 */
static int
__twopence_pipe_handshake(struct twopence_pipe_target *handle)
{
  twopence_buf_t *bp, payload;
  const twopence_hdr_t *hdr;
  twopence_protocol_state_t ps;
  int rc = 0;

  rc = __twopence_pipe_send(handle, twopence_protocol_build_hello_packet(0));
  if (rc < 0)
    return rc;

  twopence_sock_post_recvbuf_if_needed(handle->link_sock, 4 * TWOPENCE_PROTO_MAX_PACKET);

  if ((bp = __twopence_pipe_read_packet(handle)) == NULL)
    return TWOPENCE_PROTOCOL_ERROR;

  if ((hdr = twopence_protocol_dissect_ps(bp, &payload, &ps)) != NULL
   && hdr->type == TWOPENCE_PROTO_TYPE_HELLO) {
    handle->ps = ps;
    rc = 0;
  } else {
    rc = TWOPENCE_PROTOCOL_ERROR;
  }

  return rc;
}

/*
 * Wrap command transaction state into a struct.
 * We may want to reuse the server side transaction code here, at some point.
 */
typedef struct twopence_pipe_stream twopence_pipe_stream_t;
struct twopence_pipe_stream {
	twopence_pipe_stream_t *next;

	int			fd;
	twopence_iostream_t *	stream;
	unsigned char		channel;	/* '0', '1', etc as used by the protocol */

	int			was_blocking;
	bool			eof;
	bool			plugged;	/* When injecting a file, we're not allowed to
						 * send before we have received the server's
						 * go-ahead. */
};

typedef struct twopence_pipe_transaction twopence_pipe_transaction_t;
struct twopence_pipe_transaction {
	struct twopence_pipe_target *handle;
	twopence_status_t	status;
	bool			done;
	bool			print_dots;

	int			state;
	twopence_protocol_state_t ps;

	unsigned int		total_data;

	twopence_pipe_stream_t *local_sources;
	twopence_pipe_stream_t *local_sinks;

	int			(*process_packet)(struct twopence_pipe_target *, twopence_pipe_transaction_t *,
						const twopence_hdr_t *hdr, twopence_buf_t *payload);
};

twopence_transaction_t *
twopence_pipe_transaction_new(struct twopence_pipe_target *handle, unsigned int type)
{
	return twopence_transaction_new(handle->link_sock, type, &handle->ps);
}

static void
twopence_pipe_transaction_init(twopence_pipe_transaction_t *trans, struct twopence_pipe_target *handle)
{
  memset(trans, 0, sizeof(*trans));
  trans->handle = handle;
  trans->ps = handle->ps;
  handle->ps.xid++;
}

static twopence_pipe_stream_t *
twopence_pipe_stream_new(twopence_iostream_t *stream, unsigned char channel)
{
  twopence_pipe_stream_t *pstream;

  pstream = calloc(1, sizeof(*pstream));
  pstream->stream = stream;
  pstream->channel = channel;
  pstream->was_blocking = -1;
  pstream->fd = -1;

  return pstream;
}

static twopence_pipe_stream_t *
twopence_pipe_stream_new_fd(int fd, unsigned char channel)
{
  twopence_pipe_stream_t *pstream;

  pstream = calloc(1, sizeof(*pstream));
  pstream->channel = channel;
  pstream->was_blocking = -1;
  pstream->fd = fd;

  return pstream;
}

static void
twopence_pipe_stream_free(twopence_pipe_stream_t *pstream)
{
  if (pstream->was_blocking >= 0 && pstream->stream) {
    twopence_iostream_set_blocking(pstream->stream, pstream->was_blocking);
  }
  free(pstream);
}

static void
twopence_pipe_stream_drop(twopence_pipe_stream_t **head)
{
  twopence_pipe_stream_t *pstream;

  while ((pstream = *head) != NULL) {
   *head = pstream->next;
   twopence_pipe_stream_free(pstream);
  }
}

twopence_pipe_stream_t *
twopence_pipe_transaction_attach_source(twopence_pipe_transaction_t *trans, twopence_iostream_t *stream, unsigned char channel)
{
  twopence_pipe_stream_t *pstream;
  int fd;

  if (trans->local_sources != NULL)
    return NULL;

  fd = twopence_iostream_getfd(stream);
  if (fd >= 0) {
    pstream = twopence_pipe_stream_new_fd(fd, channel);
  } else {
    /* The source stream is a buffer or something even more bizarre.
     * We need to handle its data synchronously.
     */
    pstream = twopence_pipe_stream_new(stream, channel);
  }

#if 0
  if (stream && channel == TWOPENCE_PROTO_TYPE_STDIN) {
    // Tune stdin so it is nonblocking.
    // Not sure whether this is actually needed any longer
    pstream->was_blocking = twopence_iostream_set_blocking(stream, false);
  }
#endif

  trans->local_sources = pstream;
  return pstream;
}

void
twopence_pipe_transaction_attach_sink(twopence_pipe_transaction_t *trans, twopence_iostream_t *stream, unsigned char channel)
{
  twopence_pipe_stream_t *pstream;

  if (stream != NULL) {
    pstream = twopence_pipe_stream_new(stream, channel);

    pstream->next = trans->local_sinks;
    trans->local_sinks = pstream;
  }
}

/*
 * Attach a local source stream to the remote stdin
 * This can be fd 0, any other file, or even a buffer object.
 */
int
twopence_pipe_transaction_attach_stdin(twopence_pipe_transaction_t *trans)
{
  twopence_iostream_t *stream;

  if (trans->local_sources != NULL)
    return TWOPENCE_PARAMETER_ERROR;

  stream = twopence_target_stream(&trans->handle->base, TWOPENCE_STDIN);
  twopence_pipe_transaction_attach_source(trans, stream, TWOPENCE_PROTO_TYPE_STDIN);
  return 0;
}

void
twopence_pipe_transaction_attach_stdout(twopence_pipe_transaction_t *trans)
{
  twopence_iostream_t *stream;

  stream = twopence_target_stream(&trans->handle->base, TWOPENCE_STDOUT);
  if (stream != NULL)
    twopence_pipe_transaction_attach_sink(trans, stream, TWOPENCE_PROTO_TYPE_STDOUT);
}

void
twopence_pipe_transaction_attach_stderr(twopence_pipe_transaction_t *trans)
{
  twopence_iostream_t *stream;

  stream = twopence_target_stream(&trans->handle->base, TWOPENCE_STDERR);
  if (stream != NULL)
    twopence_pipe_transaction_attach_sink(trans, stream, TWOPENCE_PROTO_TYPE_STDERR);
}

void
twopence_pipe_transaction_destroy(twopence_pipe_transaction_t *trans)
{
  twopence_pipe_stream_drop(&trans->local_sources);
  twopence_pipe_stream_drop(&trans->local_sinks);
}

/*
 * Forward data from a local source file to the server.
 *
 * We can have at most one local source for now, which
 * helps to keep the code a bit simpler.
 */
static int
__twopence_pipe_forward_source(twopence_pipe_transaction_t *trans, twopence_pipe_stream_t *pstream)
{
  twopence_iostream_t *stream;
  twopence_buf_t *bp;
  int count, def_error;

  if (pstream == NULL || pstream->eof || pstream->plugged)
    return 0;

  if (pstream->channel == TWOPENCE_PROTO_TYPE_STDIN)
    def_error = TWOPENCE_FORWARD_INPUT_ERROR;
  else
    def_error = TWOPENCE_SEND_FILE_ERROR;

  stream = pstream->stream;
  if (stream && twopence_iostream_eof(stream)) {
send_eof:
    if (__twopence_pipe_send_eof(trans->handle, &trans->ps) < 0)
      return def_error;

    pstream->eof = true;
    return 0;
  }

  bp = twopence_protocol_command_buffer_new();

  do {
    if (pstream->fd >= 0) {
      count = read(pstream->fd, twopence_buf_tail(bp), twopence_buf_tailroom(bp));
    } else {
      count = twopence_iostream_read(stream,
		    twopence_buf_tail(bp),
		    twopence_buf_tailroom(bp));
    }
  } while (count < 0 && errno == EINTR);

  if (count > 0) {
    twopence_buf_advance_tail(bp, count);
    twopence_protocol_push_header_ps(bp, &trans->ps, pstream->channel);
    if (__twopence_pipe_send(trans->handle, bp) < 0)
      return def_error;

    trans->total_data += count;
    if (trans->print_dots)
      __twopence_pipe_output(trans->handle, '.');
    return count;
  }

  twopence_buf_free(bp);

  if (count == 0)
    goto send_eof;

  /* Failure to read from stdin stream */
  return def_error;
}

static int
__twopence_pipe_forward_sink(twopence_pipe_transaction_t *trans, unsigned char channel, twopence_buf_t *payload)
{
  twopence_pipe_stream_t *pstream = NULL;

  for (pstream = trans->local_sinks; pstream; pstream = pstream->next) {
    if (pstream->channel == channel) {
      if (__twopence_pipe_write_stream(pstream->stream, payload) < 0)
        return TWOPENCE_RECEIVE_RESULTS_ERROR;

      trans->total_data += twopence_buf_count(payload);
      if (trans->print_dots)
        __twopence_pipe_output(trans->handle, '.');
      return 1;
    }
  }

  return 0;
}

static int
__twopence_pipe_transaction_process_incoming(twopence_pipe_transaction_t *trans, twopence_buf_t *bp)
{
  struct twopence_pipe_target *handle = trans->handle;
  twopence_protocol_state_t ps;
  const twopence_hdr_t *hdr;
  twopence_buf_t payload;
  int rc;

  /* Split the packet into header and payload */
  hdr = twopence_protocol_dissect_ps(bp, &payload, &ps);
  if (hdr == NULL)
    return TWOPENCE_PROTOCOL_ERROR;

  /* Sanity check: make sure this actually belongs to this transaction */
  if (ps.cid != trans->ps.cid || ps.xid != trans->ps.xid) {
    twopence_log_error("%s: ignoring '%c' packet with bad cid=0x%x or xid=0x%x\n",
		    __func__, hdr->type, ps.cid, ps.xid);
    return 0;
  }

  /* See if this is a generic data channel that we should just copy to
   * a local data stream */
  rc = __twopence_pipe_forward_sink(trans, hdr->type, &payload);

  /* No packet that we would have known. Pass it on */
  if (rc == 0)
    rc = trans->process_packet(handle, trans, hdr, &payload);

  return rc;
}

static int
__twopence_pipe_transaction_poll_socket(twopence_pipe_transaction_t *trans, struct pollfd *pfd)
{
  struct twopence_pipe_target *handle = trans->handle;
  twopence_sock_t *sock;
  twopence_buf_t *bp;

  if ((sock = handle->link_sock) == NULL)
    return TWOPENCE_PROTOCOL_ERROR; /* SESSION_ERROR? */

  twopence_sock_post_recvbuf_if_needed(sock, 4 * TWOPENCE_PROTO_MAX_PACKET);

  bp = twopence_sock_get_recvbuf(sock);
  if (twopence_buf_tailroom_max(bp) < TWOPENCE_PROTO_MAX_PACKET)
    twopence_buf_compact(bp);

  twopence_sock_prepare_poll(sock);
  if (!twopence_sock_fill_poll(sock, pfd)) {
    twopence_log_error("socket doesn't wait for anything?!");
    return TWOPENCE_PROTOCOL_ERROR; /* SESSION_ERROR? */
  }

  return 0;
}

static int
__twopence_pipe_transaction_doio(twopence_pipe_transaction_t *trans)
{
  struct twopence_pipe_target *handle = trans->handle;
  unsigned long timeout = handle->link_timeout;

  while (!trans->done) {
    twopence_pipe_stream_t *pstream = NULL;
    struct pollfd pfd[2];
    int nfds = 0, n;
    int count, rc;

    if ((rc = __twopence_pipe_transaction_poll_socket(trans, pfd + nfds)) < 0)
      return rc;
    nfds++;

    /*
     * Comment on the use of pstream->plugged.
     *
     * For command transactions, we should only send data in state 0.
     * For inject transactions, we should only send data after we have received the
     * MAJOR code. Thus, the local source is initially plugged in this case, and
     * unplugged later on.
     */
    if ((pstream = trans->local_sources) != NULL && !pstream->eof && !pstream->plugged) {
      if (pstream->fd >= 0) {
        pfd[nfds].events = POLLIN;
	pfd[nfds].fd = pstream->fd;
	nfds++;
      } else {
	/* We have no fd for this source stream, and hence we cannot poll.
	 * Just write data synchronously.
	 */
        count = __twopence_pipe_forward_source(trans, pstream);
	if (count <= 0)
	  return count;
	continue;
      }
    }

    n = poll(pfd, nfds, timeout);
    if (n < 0) {
      if (errno == EINTR)
	continue;
      perror("poll");
      return TWOPENCE_PROTOCOL_ERROR;
    }
    if (n == 0) {
      fprintf(stderr, "recv timeout on link\n");
      return TWOPENCE_PROTOCOL_ERROR;
    }

    if (pfd[0].revents & POLLIN) {
      /* Incoming data on the link. */
      twopence_buf_t *bp;

      bp = __twopence_pipe_read_packet(handle);
      if (bp == NULL)
        return TWOPENCE_PROTOCOL_ERROR;

      while (twopence_protocol_buffer_complete(bp)) {
        rc = __twopence_pipe_transaction_process_incoming(trans, bp);
	if (rc < 0)
          return rc;
      }
    }

    if (nfds > 1 && (pfd[1].revents & (POLLIN|POLLHUP))) {
      rc = __twopence_pipe_forward_source(trans, pstream);
      if (rc < 0)
        return rc;
    }
  }

  return 0;
}

static int
__twopence_pipe_transaction_run(twopence_pipe_transaction_t *trans, twopence_status_t *status_ret)
{
  int rc;

  do {
    rc = __twopence_pipe_transaction_doio(trans);
  } while (!trans->done && rc >= 0);

  *status_ret = trans->status;
  return rc;
}


static int
__twopence_transaction_run(struct twopence_pipe_target *handle, twopence_transaction_t *trans, twopence_status_t *status)
{
	twopence_sock_t *sock = handle->link_sock;

	while (!trans->done) {
		/* This is connection_fill_poll() */
		{
			struct pollfd pfd[16];
			unsigned int nfds = 0, max = 16;

			twopence_sock_prepare_poll(sock);

			/* Make sure we have a receive buffer posted. */
			twopence_sock_post_recvbuf_if_needed(sock, TWOPENCE_PROTO_MAX_PACKET);

			if (nfds < max && twopence_sock_fill_poll(sock, pfd + nfds))
				nfds++;

			nfds += twopence_transaction_fill_poll(trans, pfd + nfds, max - nfds);

			/* FIXME: timeout handling */
			poll(pfd, nfds, -1);
		}

		/* This is connection_doio() */
		{
			twopence_buf_t *bp;

			if (twopence_sock_doio(sock) < 0) {
				twopence_log_error("I/O error on socket: %m\n");
				goto protocol_error;
			}

			bp = twopence_sock_get_recvbuf(sock);
			while (bp && twopence_protocol_buffer_complete(bp)) {
				const twopence_hdr_t *hdr;
				twopence_protocol_state_t ps;
				twopence_buf_t payload;

				hdr = twopence_protocol_dissect_ps(bp, &payload, &ps);
				if (hdr == NULL) {
					twopence_log_error("%s: received invalid packet\n", __func__);
					goto protocol_error;
				}

				twopence_debug("%s: cid=%u xid=%u type=%c len=%u\n", __func__,
						ps.cid, ps.xid, hdr->type, twopence_buf_count(&payload));

				if (ps.xid != trans->ps.xid) {
					twopence_log_error("%s: xid mismatch", __func__);
					continue;
				}

				twopence_transaction_recv_packet(trans, hdr, &payload);
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

			twopence_transaction_doio(trans);
		}

	}

	if (trans->client.exception < 0)
		return trans->client.exception;

	return 0;

protocol_error:
	/* kill the connection? */
	return TWOPENCE_PROTOCOL_ERROR;
}

///////////////////////////// Middle layer //////////////////////////////////////
//

/*
 * Callback function that handles incoming packets for a command transaction.
 */
static int
__twopence_pipe_command_process_packet(struct twopence_pipe_target *handle, twopence_pipe_transaction_t *trans,
		const twopence_hdr_t *hdr, twopence_buf_t *payload)
{
  switch (hdr->type) {
  case TWOPENCE_PROTO_TYPE_TIMEOUT:
    if (trans->state != 0)
      return TWOPENCE_RECEIVE_RESULTS_ERROR;
    return TWOPENCE_COMMAND_TIMEOUT_ERROR;

  case TWOPENCE_PROTO_TYPE_MAJOR:
    if (trans->state != 0
     || !twopence_protocol_dissect_int(payload, &trans->status.major))
      return TWOPENCE_RECEIVE_RESULTS_ERROR;
    trans->state = 1;
    break;

  case TWOPENCE_PROTO_TYPE_MINOR:
    if (trans->state != 1
     || !twopence_protocol_dissect_int(payload, &trans->status.minor))
      return TWOPENCE_RECEIVE_RESULTS_ERROR;
    trans->state = 2;
    trans->done = true;
    break;

  default:
    return TWOPENCE_RECEIVE_RESULTS_ERROR;
  }
  return 0;
}

/*
 * Callback function that handles incoming packets for a sendfile transaction.
 */
#if 0
static int
__twopence_pipe_inject_process_packet(struct twopence_pipe_target *handle, twopence_pipe_transaction_t *trans,
		const twopence_hdr_t *hdr, twopence_buf_t *payload)
{
  switch (hdr->type) {
  case TWOPENCE_PROTO_TYPE_MAJOR:
    if (trans->state != 0
     || !twopence_protocol_dissect_int(payload, &trans->status.major))
      return TWOPENCE_RECEIVE_FILE_ERROR;

    if (trans->status.major != 0)
      return TWOPENCE_RECEIVE_FILE_ERROR;

    /* Unplug the local source file so that we can start the transfer */
    if (trans->local_sources)
      trans->local_sources->plugged = false;
    trans->state = 1;
    break;

  case TWOPENCE_PROTO_TYPE_MINOR:
    if (trans->state != 1
     || !twopence_protocol_dissect_int(payload, &trans->status.minor))
      return TWOPENCE_RECEIVE_FILE_ERROR;
    trans->state = 2;
    trans->done = true;
    break;

  default:
    return TWOPENCE_RECEIVE_FILE_ERROR;
  }
  return 0;
}
#endif

/*
 * Callback function that handles incoming packets for a sendfile transaction.
 */
static bool
__twopence_pipe_inject_recv(twopence_transaction_t *trans, const twopence_hdr_t *hdr, twopence_buf_t *payload)
{
  twopence_trans_channel_t *source;

  switch (hdr->type) {
  case TWOPENCE_PROTO_TYPE_MAJOR:
    if (!twopence_protocol_dissect_int(payload, &trans->client.status_ret.major))
      goto recv_file_error;

    if (trans->client.status_ret.major != 0)
      goto recv_file_error;

    /* Unplug the local source file so that we can start the transfer */
    if ((source = trans->local_source) != NULL)
      twopence_transaction_channel_set_plugged(source, false);
    break;

  case TWOPENCE_PROTO_TYPE_MINOR:
    if (!twopence_protocol_dissect_int(payload, &trans->client.status_ret.minor))
      goto recv_file_error;
    trans->done = true;
    break;

  default:
    goto recv_file_error;
  }
  return true;

recv_file_error:
  twopence_transaction_set_error(trans, TWOPENCE_RECEIVE_FILE_ERROR);
  return true;
}

static void
__twopence_pipe_inject_read_eof(twopence_transaction_t *trans, twopence_trans_channel_t *source)
{
  int rc;

  if ((rc = twopence_sock_xmit(trans->client_sock, twopence_protocol_build_eof_packet(&trans->ps))) < 0)
    twopence_transaction_set_error(trans, rc);
}

/*
 * Callback function that handles incoming packets for a recvfile transaction.
 */
#if 0
static int
__twopence_pipe_extract_process_packet(struct twopence_pipe_target *handle, twopence_pipe_transaction_t *trans,
		const twopence_hdr_t *hdr, twopence_buf_t *payload)
{
  switch (hdr->type) {
  case TWOPENCE_PROTO_TYPE_MAJOR:
    /* Remote error occurred, usually when trying to open the file */
    (void) twopence_protocol_dissect_int(payload, &trans->status.major);
    trans->done = true;
    return TWOPENCE_RECEIVE_FILE_ERROR;

  case TWOPENCE_PROTO_TYPE_EOF:
    /* End of data */
    trans->done = true;
    break;

  default:
    return TWOPENCE_RECEIVE_FILE_ERROR;
  }
  return 0;
}
#endif

static bool
__twopence_pipe_extract_recv(twopence_transaction_t *trans, const twopence_hdr_t *hdr, twopence_buf_t *payload)
{
  switch (hdr->type) {
  case TWOPENCE_PROTO_TYPE_MAJOR:
    /* Remote error occurred, usually when trying to open the file */
    (void) twopence_protocol_dissect_int(payload, &trans->client.status_ret.major);
    twopence_transaction_set_error(trans, TWOPENCE_RECEIVE_FILE_ERROR);
    break;

  case TWOPENCE_PROTO_TYPE_EOF:
    /* End of data */
    trans->done = true;
    break;

  default:
    twopence_transaction_set_error(trans, TWOPENCE_RECEIVE_FILE_ERROR);
    break;
  }
  return true;
}

static void
__twopence_pipe_extract_eof(twopence_transaction_t *trans, twopence_trans_channel_t *channel)
{
  twopence_debug("%s: received EOF on data", twopence_transaction_describe(trans));
  trans->done = true;
}

///////////////////////////// Top layer /////////////////////////////////////////

// Send a Linux command to the remote host
//
// Returns 0 if everything went fine, or a negative error code if failed
static int
__twopence_pipe_command
  (struct twopence_pipe_target *handle,
   const char *username, long timeout, const char *linux_command,
   twopence_status_t *status_ret)
{
  twopence_pipe_transaction_t trans;
  twopence_buf_t *bp;
  int rc;

  // By default, no major and no minor
  memset(status_ret, 0, sizeof(*status_ret));

  // Check that the username is valid
  if (_twopence_invalid_username(username))
    return TWOPENCE_PARAMETER_ERROR;

  // Refuse to execute empty commands
  if (*linux_command == '\0')
    return TWOPENCE_PARAMETER_ERROR;

  // Open communication link
  if (__twopence_pipe_open_link(handle) < 0)
    return TWOPENCE_OPEN_SESSION_ERROR;

  twopence_pipe_transaction_init(&trans, handle);
  trans.process_packet = __twopence_pipe_command_process_packet;

  // Prepare command to send to the remote host
  bp = twopence_protocol_build_command_packet(&trans.ps, username, linux_command, timeout);
  if (bp == NULL) {
    twopence_pipe_transaction_destroy(&trans);
    return TWOPENCE_PARAMETER_ERROR;
  }

  // Send command
  if (__twopence_pipe_send(handle, bp) < 0) {
    twopence_pipe_transaction_destroy(&trans);
    return TWOPENCE_SEND_COMMAND_ERROR;
  }

  /* This entire line timeout business seems not very useful, at least while
   * waiting for a command to finish - that command may sleep for minutes
   * without producing any output.
   * For now, we make sure that the link timeout is the maximum of LINE_TIMEOUT
   * and (command timeout + 1).
   */
  handle->link_timeout = (timeout + 1) * 1000;
  if (handle->link_timeout < LINE_TIMEOUT)
    handle->link_timeout = LINE_TIMEOUT;

  rc = twopence_pipe_transaction_attach_stdin(&trans);
  if (rc < 0) {
    twopence_pipe_transaction_destroy(&trans);
    return rc;
  }

  twopence_pipe_transaction_attach_stdout(&trans);
  twopence_pipe_transaction_attach_stderr(&trans);

  // Read "standard output" and "standard error"
  handle->current_transaction = &trans;
  rc = __twopence_pipe_transaction_run(&trans, status_ret);
  handle->current_transaction = NULL;

  twopence_pipe_transaction_destroy(&trans);
  return rc;
}

// Inject a file into the remote host
//
// Returns 0 if everything went fine
int __twopence_pipe_inject_file
  (struct twopence_pipe_target *handle, twopence_file_xfer_t *xfer, twopence_status_t *status)
{
  twopence_transaction_t *trans;
  twopence_trans_channel_t *channel;
  twopence_buf_t *bp;
  int fd;
  int rc;

  // Check that the username is valid
  if (_twopence_invalid_username(xfer->user))
    return TWOPENCE_PARAMETER_ERROR;
  if (xfer->local_stream == NULL)
    return TWOPENCE_PARAMETER_ERROR;

  // Open communication link
  if (__twopence_pipe_open_link(handle) < 0)
    return TWOPENCE_OPEN_SESSION_ERROR;

  trans = twopence_pipe_transaction_new(handle, TWOPENCE_PROTO_TYPE_INJECT);
  trans->recv = __twopence_pipe_inject_recv;

#ifdef later
  trans.print_dots = xfer->print_dots;
#endif

  // Prepare command to send to the remote host
  bp = twopence_protocol_build_inject_packet(&trans->ps, xfer->user, xfer->remote.name, xfer->remote.mode);

  // Send command
  if (__twopence_pipe_send(handle, bp) < 0)
    return TWOPENCE_SEND_COMMAND_ERROR;

  if ((fd = twopence_iostream_getfd(xfer->local_stream)) >= 0) {
    channel = twopence_transaction_attach_local_source(trans, fd, TWOPENCE_PROTO_TYPE_DATA);
    if (channel) {
      twopence_transaction_channel_set_callback_read_eof(channel, __twopence_pipe_inject_read_eof);
      twopence_transaction_channel_set_plugged(channel, true);
    }
  } else {
    /* Unable to use polling. Just send all data right away */
    return -100;
  }

  rc = __twopence_transaction_run(handle, trans, status);

#ifdef later
  if (trans.print_dots && trans.total_data != 0)
    __twopence_pipe_output(trans.handle, '\n');
#endif

  twopence_transaction_free(trans);
  return rc;
}

// Extract a file from the remote host
//
// Returns 0 if everything went fine, or a negative error code if failed
int _twopence_extract_virtio_serial
  (struct twopence_pipe_target *handle, twopence_file_xfer_t *xfer, twopence_status_t *status)
{
  twopence_transaction_t *trans;
  twopence_trans_channel_t *sink;
  twopence_buf_t *bp;
  int rc;

  // Check that the username is valid
  if (_twopence_invalid_username(xfer->user))
    return TWOPENCE_PARAMETER_ERROR;

  // Open link for transmitting the command
  if (__twopence_pipe_open_link(handle) < 0)
    return TWOPENCE_OPEN_SESSION_ERROR;

  trans = twopence_pipe_transaction_new(handle, TWOPENCE_PROTO_TYPE_EXTRACT);
  trans->recv = __twopence_pipe_extract_recv;

#ifdef later
  trans.print_dots = xfer->print_dots;
#endif

  // Prepare command to send to the remote host
  bp = twopence_protocol_build_extract_packet(&trans->ps, xfer->user, xfer->remote.name);

  // Send command (including terminating NUL)
  if (__twopence_pipe_send(handle, bp) < 0)
    return TWOPENCE_SEND_COMMAND_ERROR;

  sink = twopence_transaction_attach_local_sink_stream(trans, TWOPENCE_PROTO_TYPE_DATA, xfer->local_stream);
  twopence_transaction_channel_set_callback_write_eof(sink, __twopence_pipe_extract_eof);

  rc = __twopence_transaction_run(handle, trans, status);

#ifdef later
  if (trans.print_dots && trans.total_data != 0)
    __twopence_pipe_output(trans.handle, '\n');
#endif

  twopence_transaction_free(trans);
  return rc;
}

// Tell the remote test server to exit
//
// Returns 0 if everything went fine, or a negative error code if failed
int _twopence_exit_virtio_serial
  (struct twopence_pipe_target *handle)
{
  // Open link for sending interrupt command
  if (__twopence_pipe_open_link(handle) < 0)
    return TWOPENCE_OPEN_SESSION_ERROR;

  // Send command
  if (__twopence_pipe_send(handle, twopence_protocol_build_simple_packet(TWOPENCE_PROTO_TYPE_QUIT)) < 0)
    return TWOPENCE_INTERRUPT_COMMAND_ERROR;

  return 0;
}

// Interrupt current command
//
// Returns 0 if everything went fine, or a negative error code if failed
int _twopence_interrupt_virtio_serial
  (struct twopence_pipe_target *handle)
{
  twopence_pipe_transaction_t *trans;

  if ((trans = handle->current_transaction) == NULL)
    return 0;

  /* If the link is not open, there's nothing to interrupt */
  if (handle->link_sock == NULL)
    return TWOPENCE_OPEN_SESSION_ERROR;

  if (__twopence_pipe_send(handle, twopence_protocol_build_simple_packet_ps(&trans->ps, TWOPENCE_PROTO_TYPE_INTR)) < 0)
    return TWOPENCE_INTERRUPT_COMMAND_ERROR;

  return 0;
}

///////////////////////////// Public interface //////////////////////////////////

/*
 * Run a command
 *
 */
int
twopence_pipe_run_test
  (struct twopence_target *opaque_handle, twopence_command_t *cmd, twopence_status_t *status_ret)
{
  struct twopence_pipe_target *handle = (struct twopence_pipe_target *) opaque_handle;
  const char *username;
  long timeout;
  const char *command;
  int rc;

  /* Background execution of commands currently not supported on this plugin */
  if (cmd->background)
    return TWOPENCE_PARAMETER_ERROR;

  if ((command = cmd->command) == NULL)
    return TWOPENCE_PARAMETER_ERROR;
  username = cmd->user? : "root";
  timeout = cmd->timeout? : 60L;

  handle->base.current.io = cmd->iostream;

  rc = __twopence_pipe_command
           (handle, username, timeout, command, status_ret);

  return rc;
}

/*
 * Inject a file into the Virtual Machine
 *
 * Returns 0 if everything went fine
 */
int
twopence_pipe_inject_file(struct twopence_target *opaque_handle,
		twopence_file_xfer_t *xfer, twopence_status_t *status)
{
  struct twopence_pipe_target *handle = (struct twopence_pipe_target *) opaque_handle;
  int rc;

  rc = __twopence_pipe_inject_file(handle, xfer, status);
  if (rc == 0 && (status->major != 0 || status->minor != 0))
    rc = TWOPENCE_REMOTE_FILE_ERROR;

  return rc;
}

// Extract a file from the Virtual Machine
//
// Returns 0 if everything went fine
int
twopence_pipe_extract_file(struct twopence_target *opaque_handle,
		twopence_file_xfer_t *xfer, twopence_status_t *status)
{
  struct twopence_pipe_target *handle = (struct twopence_pipe_target *) opaque_handle;
  int rc;

  // Extract it
  rc = _twopence_extract_virtio_serial(handle, xfer, status);
  if (rc == 0 && (status->major != 0 || status->minor != 0))
    rc = TWOPENCE_REMOTE_FILE_ERROR;

  return rc;
}

// Interrupt current command
//
// Returns 0 if everything went fine
int
twopence_pipe_interrupt_command(struct twopence_target *opaque_handle)
{
  struct twopence_pipe_target *handle = (struct twopence_pipe_target *) opaque_handle;

  return _twopence_interrupt_virtio_serial(handle);
}

// Tell the remote test server to exit
//
// Returns 0 if everything went fine
int
twopence_pipe_exit_remote(struct twopence_target *opaque_handle)
{
  struct twopence_pipe_target *handle = (struct twopence_pipe_target *) opaque_handle;

  handle->base.current.io = NULL;

  return _twopence_exit_virtio_serial(handle);
}

// Close the library
void
twopence_pipe_end(struct twopence_target *opaque_handle)
{
  struct twopence_pipe_target *handle = (struct twopence_pipe_target *) opaque_handle;

  if (handle->link_sock != NULL) {
    twopence_sock_free(handle->link_sock);
    handle->link_sock = NULL;
  }

  free(handle);
}
