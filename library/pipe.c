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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "twopence.h"
#include "protocol.h"
#include "transaction.h"
#include "pipe.h"
#include "utils.h"

static int				__twopence_pipe_handshake(twopence_sock_t *sock, unsigned int *client_id, unsigned int *keepalive);
static void				__twopence_pipe_end_transaction(twopence_conn_t *, twopence_transaction_t *);

static twopence_conn_pool_t *		twopence_pipe_connection_pool;

static twopence_conn_semantics_t	twopence_client_semantics = {
	.end_transaction	= __twopence_pipe_end_transaction,
};

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
  target->keepalive = -1;
  target->link_ops = link_ops;
}

///////////////////////////// Lower layer ///////////////////////////////////////

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
  if (handle->connection && twopence_conn_is_closed(handle->connection))
    return TWOPENCE_TRANSPORT_ERROR;

  if (handle->connection == NULL) {
    unsigned int client_id = 0;
    unsigned int keepalive = 0;
    twopence_sock_t *sock;

    /* The socket we are given should be set up for blocking I/O */
    sock = handle->link_ops->open(handle);
    if (sock == NULL)
      return TWOPENCE_OPEN_SESSION_ERROR;

    if (handle->keepalive < 0)
      keepalive = 0xFFFF;		/* request keepalive but accept server's pick */
    else
      keepalive = handle->keepalive;
    twopence_debug("using keepalive=%u", (int) keepalive);

    if (__twopence_pipe_handshake(sock, &client_id, &keepalive) < 0) {
      twopence_sock_free(sock);
      return TWOPENCE_OPEN_SESSION_ERROR;
    }

    twopence_debug("handshake complete, my client id is %d, keepalive is %u", client_id, keepalive);
    handle->connection = twopence_conn_new(&twopence_client_semantics, sock, client_id);
    handle->ps.cid = client_id;
    handle->ps.xid = 1;

    /* If keepalive is -2, ignore the result of the keepalive negotiation and
     * force them to off.
     * This only exists so that we can test that keepalives work */
    if (handle->keepalive == -2)
      keepalive = 0;

    twopence_conn_set_keepalive(handle->connection, keepalive);

    if (twopence_pipe_connection_pool == NULL) {
      twopence_pipe_connection_pool = twopence_conn_pool_new();
      twopence_conn_pool_set_callback_close_connection(twopence_pipe_connection_pool, NULL);
    }

    twopence_conn_pool_add_connection(twopence_pipe_connection_pool, handle->connection);
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

  if (handle->connection == NULL)
    return TWOPENCE_PROTOCOL_ERROR; /* SESSION_ERROR? */

  /* FIXME: heed the link timeout */

  /* Transmit and free the buffer */
  rc = twopence_conn_xmit_packet(handle->connection, bp);
  if (rc < 0)
    return rc;

  return count;
}

/*
 * Read a chunk (normally called a packet or frame) from the link
 */
static twopence_buf_t *
__twopence_pipe_read_packet(twopence_sock_t *sock)
{
  twopence_buf_t *bp;

  bp = twopence_sock_get_recvbuf(sock);

  /* Receive more data from the link until we have at least one
   * complete packet.
   * Note: we may receive more data than that.
   */
  while (!twopence_protocol_buffer_complete(bp)) {
    int count;

    /* FIXME: heed the link timeout */
    count = twopence_sock_recv_buffer_blocking(sock, bp);
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
__twopence_pipe_handshake(twopence_sock_t *sock, unsigned int *client_id, unsigned int *line_timeout)
{
  twopence_buf_t *bp, payload;
  const twopence_hdr_t *hdr;
  twopence_protocol_state_t ps;
  unsigned char server_version[2];
  unsigned int server_keepalive;
  int rc = 0;

  /* Transmit and free the buffer */
  rc = twopence_sock_xmit(sock, twopence_protocol_build_hello_packet(0, *line_timeout));
  if (rc < 0)
    return rc;

  twopence_sock_post_recvbuf_if_needed(sock, 4 * TWOPENCE_PROTO_MAX_PACKET);

  if ((bp = __twopence_pipe_read_packet(sock)) == NULL)
    return TWOPENCE_PROTOCOL_ERROR;

  memset(&ps, 0, sizeof(ps));
  if ((hdr = twopence_protocol_dissect_ps(bp, &payload, &ps)) != NULL
   && hdr->type == TWOPENCE_PROTO_TYPE_HELLO
   && twopence_protocol_dissect_hello_packet(&payload, server_version, &server_keepalive)) {
    twopence_debug("received server HELLO reply: version %u.%u, keepalive=%u",
		    server_version[0], server_version[1], server_keepalive);
    if (server_version[0] != TWOPENCE_PROTOCOL_VERSMAJOR
     || server_version[1] < TWOPENCE_PROTOCOL_VERSMINOR) {
      twopence_log_error("Protocol version not compatible. We use %u.%u, server uses %u.%u",
	      TWOPENCE_PROTOCOL_VERSMAJOR, TWOPENCE_PROTOCOL_VERSMINOR, server_version[0], server_version[1]);
      return TWOPENCE_INCOMPATIBLE_PROTOCOL_ERROR;
    }
    *client_id = ps.cid;
    if (*line_timeout == 0 || server_keepalive < *line_timeout)
      *line_timeout = server_keepalive;
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
static twopence_transaction_t *
twopence_pipe_transaction_new(struct twopence_pipe_target *handle, unsigned int type)
{
  twopence_transaction_t *trans;

  trans = twopence_conn_transaction_new(handle->connection, type, &handle->ps);
  if (trans)
	  handle->ps.xid++;
  return trans;
}

/*
 * A local source has hit EOF; send the EOF indication to the remote.
 */
static void
__twopence_pipe_local_source_eof(twopence_transaction_t *trans, twopence_trans_channel_t *source)
{
  uint16_t channel_id = twopence_transaction_channel_id(source);
  twopence_buf_t *bp;
  int rc;

  bp = twopence_protocol_build_eof_packet(&trans->ps, channel_id);
  if ((rc = twopence_sock_xmit(trans->socket, bp)) < 0) {
    twopence_transaction_set_error(trans, rc);
    twopence_buf_free(bp);
  }
}


/*
 * Attach a local source stream to the remote stdin
 * This can be fd 0, any other file, or even a buffer object.
 */
static void
__twopence_pipe_transaction_attach_stdin(twopence_transaction_t *trans, twopence_iostream_t *stream)
{
  twopence_trans_channel_t *channel;

  channel = twopence_transaction_attach_local_source_stream(trans, TWOPENCE_STDIN, stream);
  if (channel) {
    twopence_transaction_channel_set_name(channel, "stdin");
    twopence_transaction_channel_set_callback_read_eof(channel, __twopence_pipe_local_source_eof);
    twopence_iostream_set_blocking(stream, false);
    /* FIXME: need to set it back to original blocking state at some point */
  }
}

static void
twopence_pipe_transaction_attach_stdin(twopence_transaction_t *trans, twopence_command_t *cmd)
{
  __twopence_pipe_transaction_attach_stdin(trans, &cmd->iostream[TWOPENCE_STDIN]);
}

static void
twopence_pipe_transaction_attach_stdout(twopence_transaction_t *trans, twopence_command_t *cmd)
{
  twopence_trans_channel_t *channel;

  twopence_iostream_t *stream = &cmd->iostream[TWOPENCE_STDOUT];
  channel = twopence_transaction_attach_local_sink_stream(trans, TWOPENCE_STDOUT, stream);
  if (channel)
    twopence_transaction_channel_set_name(channel, "stdout");
}

static void
twopence_pipe_transaction_attach_stderr(twopence_transaction_t *trans, twopence_command_t *cmd)
{
  twopence_trans_channel_t *channel;

  twopence_iostream_t *stream = &cmd->iostream[TWOPENCE_STDERR];
  channel = twopence_transaction_attach_local_sink_stream(trans, TWOPENCE_STDERR, stream);
  if (channel)
    twopence_transaction_channel_set_name(channel, "stderr");
}

static void
__twopence_pipe_end_transaction(twopence_conn_t *conn, twopence_transaction_t *trans)
{
  twopence_debug("%s: transaction done, move it to wait list", twopence_transaction_describe(trans));
  twopence_conn_add_transaction_done(conn, trans);
}

static void
__twopence_pipe_transaction_add_running(struct twopence_pipe_target *handle, twopence_transaction_t *trans)
{
  twopence_conn_add_transaction(handle->connection, trans);
}

static twopence_transaction_t *
__twopence_pipe_get_completed_transaction(struct twopence_pipe_target *handle, int xid)
{
  return twopence_conn_reap_transaction(handle->connection, xid);
}

int
__twopence_pipe_doio(struct twopence_pipe_target *handle)
{
  twopence_conn_pool_poll(twopence_pipe_connection_pool);
  if (twopence_conn_is_closed(handle->connection))
    return TWOPENCE_TRANSPORT_ERROR;

  return 0;
}

static int
__twopence_transaction_run(struct twopence_pipe_target *handle, twopence_transaction_t *trans, twopence_status_t *status)
{
  int xid = trans->id;
  int rc;

  while (true) {
    if (handle->connection == NULL)
      return TWOPENCE_TRANSPORT_ERROR; /* shouldn't happen */

    if (twopence_conn_reap_transaction(handle->connection, xid) != NULL)
      break;

    if ((rc = __twopence_pipe_doio(handle)) < 0) {
      /* Oops, transport error.
       * Cancel all transaction and mark them as failed */
      twopence_conn_cancel_transactions(handle->connection, rc);
      continue;
    }
  }

  *status = trans->client.status_ret;
  if (trans->client.exception < 0)
    return trans->client.exception;

  return 0;
}

///////////////////////////// Middle layer //////////////////////////////////////
//

/*
 * Callback function that handles incoming packets for a command transaction.
 */
static bool
__twopence_pipe_command_recv(twopence_transaction_t *trans, const twopence_hdr_t *hdr, twopence_buf_t *payload)
{
  switch (hdr->type) {
  case TWOPENCE_PROTO_TYPE_TIMEOUT:
    twopence_transaction_set_error(trans, TWOPENCE_COMMAND_TIMEOUT_ERROR);
    break;

  case TWOPENCE_PROTO_TYPE_MAJOR:
    if (!twopence_protocol_dissect_major_packet(payload, &trans->client.status_ret.major))
      goto receive_results_error;
    break;

  case TWOPENCE_PROTO_TYPE_MINOR:
    if (!twopence_protocol_dissect_minor_packet(payload, &trans->client.status_ret.minor))
      goto receive_results_error;
    trans->done = true;
    break;

  default:
    goto receive_results_error;
  }
  return true;

receive_results_error:
  twopence_transaction_set_error(trans, TWOPENCE_RECEIVE_RESULTS_ERROR);
  return true;
}

/*
 * Callback function that handles incoming packets for a sendfile transaction.
 */
static bool
__twopence_pipe_inject_recv(twopence_transaction_t *trans, const twopence_hdr_t *hdr, twopence_buf_t *payload)
{
  twopence_trans_channel_t *source;

  switch (hdr->type) {
  case TWOPENCE_PROTO_TYPE_MAJOR:
    if (!twopence_protocol_dissect_major_packet(payload, &trans->client.status_ret.major))
      goto recv_file_error;

    if (trans->client.status_ret.major != 0)
      goto recv_file_error;

    /* Unplug the local source file so that we can start the transfer */
    if ((source = trans->local_source) != NULL)
      twopence_transaction_channel_set_plugged(source, false);
    break;

  case TWOPENCE_PROTO_TYPE_MINOR:
    if (!twopence_protocol_dissect_minor_packet(payload, &trans->client.status_ret.minor))
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

static bool
__twopence_pipe_extract_recv(twopence_transaction_t *trans, const twopence_hdr_t *hdr, twopence_buf_t *payload)
{
  switch (hdr->type) {
  case TWOPENCE_PROTO_TYPE_MAJOR:
    /* Remote error occurred, usually when trying to open the file */
    (void) twopence_protocol_dissect_major_packet(payload, &trans->client.status_ret.major);
    twopence_transaction_set_error(trans, TWOPENCE_RECEIVE_FILE_ERROR);
    break;

  case TWOPENCE_PROTO_TYPE_CHAN_EOF:
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
__twopence_pipe_command(struct twopence_pipe_target *handle, twopence_command_t *cmd, twopence_status_t *status_ret)
{
  twopence_transaction_t *trans;
  int rc;

  // Check that the username is valid
  if (_twopence_invalid_username(cmd->user))
    return TWOPENCE_PARAMETER_ERROR;

  // Refuse to execute empty commands
  if (cmd->command == NULL || *cmd->command == '\0')
    return TWOPENCE_PARAMETER_ERROR;

  // Open communication link
  if (__twopence_pipe_open_link(handle) < 0)
    return TWOPENCE_OPEN_SESSION_ERROR;

  trans = twopence_pipe_transaction_new(handle, TWOPENCE_PROTO_TYPE_COMMAND);
  trans->recv = __twopence_pipe_command_recv;

  // Send command packet
  if ((rc = twopence_transaction_send_command(trans, cmd)) < 0)
    goto out;

  if (cmd->timeout)
    twopence_transaction_set_timeout(trans, cmd->timeout);

  twopence_pipe_transaction_attach_stdin(trans, cmd);
  twopence_pipe_transaction_attach_stdout(trans, cmd);
  twopence_pipe_transaction_attach_stderr(trans, cmd);

  __twopence_pipe_transaction_add_running(handle, trans);

  /* If we've been asked to run the command in the background,
   * return its XID now. */
  if (cmd->background) {
    twopence_debug("backgrounding transaction %d (return pid %d)",
		    twopence_transaction_describe(trans), trans->id);
    return trans->id;
  }

  handle->current_transaction = trans;
  rc = __twopence_transaction_run(handle, trans, status_ret);
  handle->current_transaction = NULL;

out:
  twopence_transaction_free(trans);
  return rc;
}

/*
 * Chat scripting: send some data
 */
int
twopence_pipe_chat_send(twopence_target_t *opaque_handle, int xid, twopence_iostream_t *stream)
{
  struct twopence_pipe_target *handle = (struct twopence_pipe_target *) opaque_handle;
  twopence_trans_channel_t *channel;
  twopence_transaction_t *trans;

  /* Should not happen: */
  if (handle->connection == NULL)
    return TWOPENCE_TRANSPORT_ERROR;

  trans = twopence_conn_find_transaction(handle->connection, xid);
  if (trans == NULL)
    return TWOPENCE_INVALID_TRANSACTION;

  twopence_transaction_close_source(trans, TWOPENCE_STDIN);
  __twopence_pipe_transaction_attach_stdin(trans, stream);

  channel = twopence_transaction_attach_local_source_stream(trans, TWOPENCE_STDIN, stream);
  if (channel) {
    twopence_transaction_channel_set_name(channel, "stdin");
    /* Do NOT set the eof callback to __twopence_pipe_local_source_eof because we
     * do NOT want to send and EOF indication when we've drained the send buffer.
     */
  }
  return 0;
}

int
twopence_pipe_chat_recv(twopence_target_t *opaque_handle, int xid, const struct timeval *deadline)
{
  struct twopence_pipe_target *handle = (struct twopence_pipe_target *) opaque_handle;
  twopence_transaction_t *trans;
  unsigned int nreceived;

  /* Should not happen: */
  if (handle->connection == NULL)
    return TWOPENCE_TRANSPORT_ERROR;

  trans = twopence_conn_find_transaction(handle->connection, xid);
  if (trans == NULL)
    return TWOPENCE_INVALID_TRANSACTION;

  nreceived = trans->stats.nbytes_received;
  while (!trans->done && nreceived == trans->stats.nbytes_received && trans->local_sink != 0) {
    int rc;

    if (!twopence_conn_has_pending_transactions(handle->connection))
      break;

    trans->client.chat_deadline = deadline;
    rc = __twopence_pipe_doio(handle);
    trans->client.chat_deadline = NULL;

    if (rc < 0)
      return rc;
  }

  return trans->stats.nbytes_received - nreceived;
}

// Inject a file into the remote host
//
// Returns 0 if everything went fine
static int
__twopence_pipe_inject_file(struct twopence_pipe_target *handle, twopence_file_xfer_t *xfer, twopence_status_t *status)
{
  twopence_transaction_t *trans;
  twopence_trans_channel_t *channel;
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

  // Send inject command packet
  if ((rc = twopence_transaction_send_inject(trans, xfer)) < 0)
    goto out;

  channel = twopence_transaction_attach_local_source_stream(trans, 0, xfer->local_stream);
  if (channel) {
    twopence_transaction_channel_set_callback_read_eof(channel, __twopence_pipe_local_source_eof);
    twopence_transaction_channel_set_plugged(channel, true);

    trans->client.print_dots = xfer->print_dots;
  }

  __twopence_pipe_transaction_add_running(handle, trans);

  rc = __twopence_transaction_run(handle, trans, status);

out:
  twopence_transaction_free(trans);
  return rc;
}

// Extract a file from the remote host
//
// Returns 0 if everything went fine, or a negative error code if failed
static int
__twopence_pipe_extract_file(struct twopence_pipe_target *handle, twopence_file_xfer_t *xfer,
				twopence_status_t *status)
{
  twopence_transaction_t *trans;
  twopence_trans_channel_t *sink;
  int rc;

  // Check that the username is valid
  if (_twopence_invalid_username(xfer->user))
    return TWOPENCE_PARAMETER_ERROR;
  if (xfer->remote.name == NULL)
    return TWOPENCE_PARAMETER_ERROR;

  // Open link for transmitting the command
  if (__twopence_pipe_open_link(handle) < 0)
    return TWOPENCE_OPEN_SESSION_ERROR;

  trans = twopence_pipe_transaction_new(handle, TWOPENCE_PROTO_TYPE_EXTRACT);
  trans->recv = __twopence_pipe_extract_recv;

  // Send command packet
  if ((rc = twopence_transaction_send_extract(trans, xfer)) < 0)
    goto out;

  sink = twopence_transaction_attach_local_sink_stream(trans, 0, xfer->local_stream);
  if (sink) {
    twopence_transaction_channel_set_callback_write_eof(sink, __twopence_pipe_extract_eof);

    trans->client.print_dots = xfer->print_dots;
  }

  __twopence_pipe_transaction_add_running(handle, trans);

  rc = __twopence_transaction_run(handle, trans, status);

out:
  twopence_transaction_free(trans);
  return rc;
}

//
static int
__twopence_pipe_disconnect(struct twopence_pipe_target *handle)
{
  if (handle->connection) {
    twopence_conn_close(handle->connection);
    twopence_conn_cancel_transactions(handle->connection, TWOPENCE_TRANSPORT_ERROR);
  }
  return 0;
}

static int
__twopence_pipe_cancel_transactions(struct twopence_pipe_target *handle)
{
  if (handle->connection)
    twopence_conn_cancel_transactions(handle->connection, TWOPENCE_COMMAND_CANCELED_ERROR);
  return 0;
}

// Tell the remote test server to exit
//
// Returns 0 if everything went fine, or a negative error code if failed
static int
__twopence_pipe_exit_remote(struct twopence_pipe_target *handle)
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
static int
__twopence_pipe_interrupt_command(struct twopence_pipe_target *handle)
{
  twopence_transaction_t *trans;

  if ((trans = handle->current_transaction) == NULL)
    return 0;

  /* If the link is not open, there's nothing to interrupt */
  if (handle->connection == NULL)
    return TWOPENCE_OPEN_SESSION_ERROR;

  if (__twopence_pipe_send(handle, twopence_protocol_build_simple_packet_ps(&trans->ps, TWOPENCE_PROTO_TYPE_INTR)) < 0)
    return TWOPENCE_INTERRUPT_COMMAND_ERROR;

  return 0;
}

///////////////////////////// Public interface //////////////////////////////////

int
twopence_pipe_set_option(struct twopence_target *opaque_handle, int option, const void *value_p)
{
  struct twopence_pipe_target *handle = (struct twopence_pipe_target *) opaque_handle;

  switch (option) {
  case TWOPENCE_TARGET_OPTION_KEEPALIVE:
    if (handle->connection != NULL) {
      twopence_log_error("%s: cannot set keepalive option; connection already established", handle->base.ops->name);
      return TWOPENCE_UNSUPPORTED_FUNCTION_ERROR; /* not quite */
    }

    handle->keepalive = *(const int *) value_p;
    break;

  default:
    return TWOPENCE_UNSUPPORTED_FUNCTION_ERROR;

  }

  return 0;
}

/*
 * Run a command
 *
 */
int
twopence_pipe_run_test(struct twopence_target *opaque_handle, twopence_command_t *cmd,
			twopence_status_t *status_ret)
{
  struct twopence_pipe_target *handle = (struct twopence_pipe_target *) opaque_handle;

  return __twopence_pipe_command(handle, cmd, status_ret);
}

/*
 * Wait for a remote command to finish
 */
int
twopence_pipe_wait(struct twopence_target *opaque_handle, int want_pid, twopence_status_t *status)
{
  struct twopence_pipe_target *handle = (struct twopence_pipe_target *) opaque_handle;
  twopence_transaction_t *trans = NULL;
  int rc;

  if (handle->connection == NULL)
    return 0;

  twopence_debug("%s: waiting for pid %d", __func__, want_pid);
  while (true) {
    trans = __twopence_pipe_get_completed_transaction(handle, want_pid);
    if (trans != NULL)
      break;

    if (!twopence_conn_has_pending_transactions(handle->connection))
      break;

    rc = __twopence_pipe_doio(handle);
    if (rc < 0)
      return rc;
  }

  if (trans == NULL)
    return 0;

  twopence_debug("%s: returning status for transaction %s", __func__, twopence_transaction_describe(trans));
  if (trans->client.exception < 0) {
    rc = trans->client.exception;
  } else {
    *status = trans->client.status_ret;
    rc = trans->id;
  }

  twopence_transaction_free(trans);
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
  rc = __twopence_pipe_extract_file(handle, xfer, status);
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

  return __twopence_pipe_interrupt_command(handle);
}

/*
 * Cancel all pending transactions
 */
int
twopence_pipe_cancel_transactions(twopence_target_t *opaque_handle)
{
  struct twopence_pipe_target *handle = (struct twopence_pipe_target *) opaque_handle;

  return __twopence_pipe_cancel_transactions(handle);
}

/*
 * Disconnect from the SUT
 */
int
twopence_pipe_disconnect(twopence_target_t *opaque_handle)
{
  struct twopence_pipe_target *handle = (struct twopence_pipe_target *) opaque_handle;

  return __twopence_pipe_disconnect(handle);
}

// Tell the remote test server to exit
//
// Returns 0 if everything went fine
int
twopence_pipe_exit_remote(struct twopence_target *opaque_handle)
{
  struct twopence_pipe_target *handle = (struct twopence_pipe_target *) opaque_handle;

  return __twopence_pipe_exit_remote(handle);
}

// Close the library
void
twopence_pipe_end(struct twopence_target *opaque_handle)
{
  struct twopence_pipe_target *handle = (struct twopence_pipe_target *) opaque_handle;

  twopence_debug("%s()", __func__);
  if (handle->connection != NULL) {
    /* The connection may still be attached to twopence_pipe_connection_pool,
     * but fortunately, twopence_conn_free() takes care of this.
     */
    twopence_conn_free(handle->connection);
    handle->connection = NULL;
  }

  free(handle);
}
