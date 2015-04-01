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
#include "utils.h"

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
twopence_transaction_t *
twopence_pipe_transaction_new(struct twopence_pipe_target *handle, unsigned int type)
{
	return twopence_transaction_new(handle->link_sock, type, &handle->ps);
}

/*
 * Attach a local source stream to the remote stdin
 * This can be fd 0, any other file, or even a buffer object.
 */
static void
__twopence_pipe_stdin_read_eof(twopence_transaction_t *trans, twopence_trans_channel_t *source)
{
  int rc;

  if ((rc = twopence_sock_xmit(trans->socket, twopence_protocol_build_eof_packet(&trans->ps))) < 0)
    twopence_transaction_set_error(trans, rc);
}

static void
twopence_pipe_transaction_attach_stdin(twopence_transaction_t *trans, twopence_command_t *cmd)
{
  twopence_iostream_t *stream = &cmd->iostream[TWOPENCE_STDIN];
  twopence_trans_channel_t *channel;

  channel = twopence_transaction_attach_local_source_stream(trans, TWOPENCE_PROTO_TYPE_STDIN, stream);
  if (channel) {
    twopence_transaction_channel_set_callback_read_eof(channel, __twopence_pipe_stdin_read_eof);
    twopence_iostream_set_blocking(stream, false);
    /* FIXME: need to set it back to original blocking state at some point */
  }
}

static void
twopence_pipe_transaction_attach_stdout(twopence_transaction_t *trans, twopence_command_t *cmd)
{
  twopence_iostream_t *stream = &cmd->iostream[TWOPENCE_STDOUT];
  twopence_transaction_attach_local_sink_stream(trans, TWOPENCE_PROTO_TYPE_STDOUT, stream);
}

static void
twopence_pipe_transaction_attach_stderr(twopence_transaction_t *trans, twopence_command_t *cmd)
{
  twopence_iostream_t *stream = &cmd->iostream[TWOPENCE_STDERR];
  twopence_transaction_attach_local_sink_stream(trans, TWOPENCE_PROTO_TYPE_STDERR, stream);
}

static int
__twopence_transaction_run(struct twopence_pipe_target *handle, twopence_transaction_t *trans, twopence_status_t *status)
{
	twopence_sock_t *sock = handle->link_sock;
	int rc;

	while (!trans->done) {
		/* This is connection_fill_poll() */
		{
			struct pollfd pfd[16];
			twopence_pollinfo_t poll_info;

			twopence_pollinfo_init(&poll_info, pfd, 16);

			twopence_sock_prepare_poll(sock);

			/* Make sure we have a receive buffer posted. */
			twopence_sock_post_recvbuf_if_needed(sock, TWOPENCE_PROTO_MAX_PACKET);

			twopence_sock_fill_poll(sock, &poll_info);
			if ((rc = twopence_transaction_fill_poll(trans, &poll_info)) < 0) {
				/* most likely a timeout */
				twopence_transaction_set_error(trans, rc);
				break;
			}

			twopence_pollinfo_poll(&poll_info);
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

			if (!trans->done)
				twopence_transaction_doio(trans);
		}

	}

	*status = trans->client.status_ret;
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
static bool
__twopence_pipe_command_recv(twopence_transaction_t *trans, const twopence_hdr_t *hdr, twopence_buf_t *payload)
{
  switch (hdr->type) {
  case TWOPENCE_PROTO_TYPE_TIMEOUT:
    twopence_transaction_set_error(trans, TWOPENCE_COMMAND_TIMEOUT_ERROR);
    break;

  case TWOPENCE_PROTO_TYPE_MAJOR:
    if (!twopence_protocol_dissect_int(payload, &trans->client.status_ret.major))
      goto receive_results_error;
    break;

  case TWOPENCE_PROTO_TYPE_MINOR:
    if (!twopence_protocol_dissect_int(payload, &trans->client.status_ret.minor))
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

  if ((rc = twopence_sock_xmit(trans->socket, twopence_protocol_build_eof_packet(&trans->ps))) < 0)
    twopence_transaction_set_error(trans, rc);
}

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
__twopence_pipe_command(struct twopence_pipe_target *handle, twopence_command_t *cmd, twopence_status_t *status_ret)
{
  twopence_transaction_t *trans;
  int rc;

  // By default, no major and no minor
  memset(status_ret, 0, sizeof(*status_ret));

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
  if ((rc = twopence_transaction_send_command(trans, cmd->user, cmd->command, cmd->timeout)) < 0)
    goto out;

  /* This entire line timeout business seems not very useful, at least while
   * waiting for a command to finish - that command may sleep for minutes
   * without producing any output.
   * For now, we make sure that the link timeout is the maximum of LINE_TIMEOUT
   * and (command timeout + 1).
   */
  if (cmd->timeout)
    twopence_transaction_set_timeout(trans, cmd->timeout);
  handle->link_timeout = (cmd->timeout + 1) * 1000;
  if (handle->link_timeout < LINE_TIMEOUT)
    handle->link_timeout = LINE_TIMEOUT;

  twopence_pipe_transaction_attach_stdin(trans, cmd);
  twopence_pipe_transaction_attach_stdout(trans, cmd);
  twopence_pipe_transaction_attach_stderr(trans, cmd);

  handle->current_transaction = trans;
  rc = __twopence_transaction_run(handle, trans, status_ret);
  handle->current_transaction = NULL;

out:
  twopence_transaction_free(trans);
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
  if ((rc = twopence_transaction_send_inject(trans, xfer->user, xfer->remote.name, xfer->remote.mode)) < 0)
    goto out;

  channel = twopence_transaction_attach_local_source_stream(trans, TWOPENCE_PROTO_TYPE_DATA, xfer->local_stream);
  if (channel) {
    twopence_transaction_channel_set_callback_read_eof(channel, __twopence_pipe_inject_read_eof);
    twopence_transaction_channel_set_plugged(channel, true);

    if (xfer->print_dots)
      twopence_transaction_set_dot_stream(trans, twopence_target_stream(&handle->base, TWOPENCE_STDOUT));
  }

  rc = __twopence_transaction_run(handle, trans, status);

out:
  twopence_transaction_set_dot_stream(trans, NULL);
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
  if ((rc = twopence_transaction_send_extract(trans, xfer->user, xfer->remote.name)) < 0)
    goto out;

  sink = twopence_transaction_attach_local_sink_stream(trans, TWOPENCE_PROTO_TYPE_DATA, xfer->local_stream);
  if (sink) {
    twopence_transaction_channel_set_callback_write_eof(sink, __twopence_pipe_extract_eof);

    if (xfer->print_dots)
      twopence_transaction_set_dot_stream(trans, twopence_target_stream(&handle->base, TWOPENCE_STDOUT));
  }

  rc = __twopence_transaction_run(handle, trans, status);

out:
  twopence_transaction_set_dot_stream(trans, NULL);
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
  twopence_transaction_t *trans;

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

  /* Background execution of commands currently not supported on this plugin */
  if (cmd->background)
    return TWOPENCE_PARAMETER_ERROR;

  handle->base.current.io = cmd->iostream;
  return __twopence_pipe_command(handle, cmd, status_ret);
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
