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
#include "pipe.h"

#define BUFFER_SIZE 32768              // Size in bytes of the work buffer for receiving data from the remote
#define LINE_TIMEOUT 60000             // Maximum silence on the line in milliseconds
#define COMMAND_BUFFER_SIZE 8192       // Size in bytes of the work buffer for sending data to the remote

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
  target->link_fd = -1;
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
  if (handle->link_fd < 0)
    handle->link_fd = handle->link_ops->open(handle);
  return handle->link_fd;
}

static inline int
__twopence_pipe_poll(int link_fd, int events, unsigned long timeout)
{
  struct pollfd pfd;
  int n;

  /* It's not quite clear why we're not just using blocking input here. --okir
   *
   * Well, it is blocking input. Quoting "man 2 poll":
   *     If none of the events requested (and no error) has occurred for any of
   *     the file descriptors, then poll() blocks until one of the events occurs.
   * or did you mean something else? --ebischoff
   */
  pfd.fd = link_fd;
  pfd.events = events;

  n = poll(&pfd, 1, timeout);
  if ((n == 1) && !(pfd.revents & events))
    n = 0;

  return n;
}

static int
__twopence_pipe_recvbuf(struct twopence_pipe_target *handle, int link_fd, char *buffer, size_t size)
{
  size_t received = 0;

  memset(buffer, 0, size);

  while (received < size) {
    int n, rc;

    n = __twopence_pipe_poll(link_fd, POLLIN, handle->link_timeout);
    if (n < 0) {
      perror("poll error");
      return TWOPENCE_PROTOCOL_ERROR;
    }

    if (n == 0) {
      fprintf(stderr, "timeout on link");
      return TWOPENCE_PROTOCOL_ERROR;
    }

    /* Read some data from the link */
    rc = handle->link_ops->recv(handle, link_fd, buffer + received, size - received);
    if (rc < 0)
      return rc;

    if (rc == 0) {
      fprintf(stderr, "unexpected EOF on link");
      return TWOPENCE_PROTOCOL_ERROR;
    }

    received += rc;
  }

  return received;
}

static int
__twopence_pipe_sendbuf(struct twopence_pipe_target *handle, int link_fd, const char *buffer, size_t count)
{
  size_t sent = 0;

  while (sent < count) {
    int n, rc;

    n = __twopence_pipe_poll(link_fd, POLLOUT, handle->link_timeout);
    if (n < 0) {
      perror("poll error");
      return TWOPENCE_PROTOCOL_ERROR;
    }

    if (n == 0) {
      fprintf(stderr, "timeout on link");
      return TWOPENCE_PROTOCOL_ERROR;
    }

    rc = handle->link_ops->send(handle, link_fd, buffer + sent, count - sent);
    if (rc < 0)
      return rc;

    sent += rc;
  }

  return sent;
}

/*
 * For now, this is just a simple wrapper around __twopence_pipe_sendbuf.
 * But down the road, this will become a front-end to feed packets into the
 * send loop, which will be fully multiplexed and poll based.
 */
static int
__twopence_pipe_send(struct twopence_pipe_target *handle, twopence_buf_t *bp)
{
  int rc;

  rc = __twopence_pipe_sendbuf(handle, handle->link_fd, twopence_buf_head(bp), twopence_buf_count(bp));
  twopence_buf_free(bp);

  return rc;
}

static int
__twopence_pipe_send_eof(struct twopence_pipe_target *handle)
{
  return __twopence_pipe_send(handle, twopence_protocol_build_eof_packet());
}

/*
 * Read a chunk (normally called a packet or frame) from the link
 */
static twopence_buf_t *
__twopence_pipe_read_packet(struct twopence_pipe_target *handle)
{
  twopence_buf_t *bp;

  bp = twopence_buf_new(TWOPENCE_PROTO_MAX_PACKET);
  while (true) {
    int need;

    need = twopence_protocol_buffer_need_to_recv(bp);
    if (need == 0)
      break;

    if (need < 0)
      goto failed;

    if (need > twopence_buf_tailroom(bp)) {
      fprintf(stderr, "Incoming packet larger than buffer (%u > %u)\n",
		      twopence_buf_count(bp) + need,
		      bp->size);
      goto failed;
    }

    if (__twopence_pipe_recvbuf(handle, handle->link_fd, twopence_buf_tail(bp), need) < 0)
      goto failed;

    twopence_buf_advance_tail(bp, need);
  }

  return bp;

failed:
  twopence_buf_free(bp);
  return NULL;
}

/*
 * Wrap command transaction state into a struct.
 * We may want to reuse the server side transaction code here, at some point.
 */
typedef struct twopence_pipe_transaction twopence_pipe_transaction_t;
struct twopence_pipe_transaction {
	bool			done;
	twopence_status_t	status;

	int			state;
	twopence_iostream_t *	stdin;

	int			(*process_packet)(struct twopence_pipe_target *, twopence_pipe_transaction_t *, twopence_buf_t *);
};

void
twopence_pipe_transaction_init(twopence_pipe_transaction_t *trans, twopence_iostream_t *stdin_stream)
{
  memset(trans, 0, sizeof(*trans));
  trans->stdin = stdin_stream;
}

void
twopence_pipe_transaction_close_stdin(twopence_pipe_transaction_t *trans)
{
  if (trans->stdin) {
    twopence_iostream_destroy(trans->stdin);
    trans->stdin = NULL;
  }
}

void
twopence_pipe_transaction_destroy(twopence_pipe_transaction_t *trans)
{
  twopence_pipe_transaction_close_stdin(trans);
}

/*
 * Helper functions to read from either link or stdin
 */
static int
__twopence_pipe_forward_stdin(struct twopence_pipe_target *handle, twopence_pipe_transaction_t *trans)
{
  twopence_buf_t *bp;
  int count;

  if (trans->stdin == NULL)
    return 0;

  if (twopence_iostream_eof(trans->stdin)) {
send_eof:
    twopence_pipe_transaction_close_stdin(trans);
    if (__twopence_pipe_send_eof(handle) < 0)
      return TWOPENCE_FORWARD_INPUT_ERROR;
    return 0;
  }

  bp = twopence_protocol_command_buffer_new();

  do {
	  count = twopence_iostream_read(trans->stdin,
		    twopence_buf_tail(bp),
		    twopence_buf_tailroom(bp));
  } while (count < 0 && errno == EINTR);

  if (count > 0) {
    twopence_buf_advance_tail(bp, count);
    twopence_protocol_push_header(bp, TWOPENCE_PROTO_TYPE_STDIN);
    if (__twopence_pipe_send(handle, bp) < 0)
      return TWOPENCE_FORWARD_INPUT_ERROR;
    return count;
  }

  twopence_buf_free(bp);

  if (count == 0)
    goto send_eof;

  /* Failure to read from stdin stream */
  return TWOPENCE_FORWARD_INPUT_ERROR;
}

static int
__twopence_pipe_recvbuf_both(struct twopence_pipe_target *handle, twopence_pipe_transaction_t *trans)
{
  unsigned long timeout = handle->link_timeout;

  while (!trans->done) {
    struct pollfd pfd[2];
    int nfds = 0, n;
    int count, rc;

    pfd[nfds].fd = handle->link_fd;
    pfd[nfds].events = POLLIN;
    nfds++;

    if (trans->stdin && trans->state == 0) {
      n = twopence_iostream_poll(trans->stdin, &pfd[nfds], POLLIN);
      if (n == 0) {
	/* A zero return code indicates the stream does not support polling,
	 * which is the case of a buffer for instance.
	 * Try to read from it directly.
	 */
        count = __twopence_pipe_forward_stdin(handle, trans);
	if (count != 0)
	  return count;
      } else
      if (n > 0)
        nfds++;
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
      /* Incoming data on the link. Read the complete frame right away (blocking until we have it) */
      twopence_buf_t *bp;

      bp = __twopence_pipe_read_packet(handle);
      if (bp == NULL)
        return TWOPENCE_PROTOCOL_ERROR;

      rc = trans->process_packet(handle, trans, bp);
      twopence_buf_free(bp);
      if (rc < 0)
        return rc;
    }

    if (nfds > 1 && (pfd[1].revents & (POLLIN|POLLHUP))) {
      rc = __twopence_pipe_forward_stdin(handle, trans);
      if (rc < 0)
        return rc;
    }
  }

  return 0;
}

///////////////////////////// Middle layer //////////////////////////////////////
// Read stdin, stdout, stderr, and both error codes
//
// Returns 0 if everything went fine, or a negative error code if failed
static int
__twopence_pipe_command_process_packet(struct twopence_pipe_target *handle, twopence_pipe_transaction_t *trans, twopence_buf_t *bp)
{
  const twopence_hdr_t *hdr;
  twopence_buf_t payload;

  hdr = twopence_protocol_dissect(bp, &payload);
  if (hdr == NULL)
    return TWOPENCE_PROTOCOL_ERROR;

  switch (hdr->type) {
  case TWOPENCE_PROTO_TYPE_STDOUT:
    if (trans->state != 0)
      return TWOPENCE_RECEIVE_RESULTS_ERROR;
    if (__twopence_pipe_write(handle, TWOPENCE_STDOUT, &payload) < 0)
      return TWOPENCE_RECEIVE_RESULTS_ERROR;
    break;

  case TWOPENCE_PROTO_TYPE_STDERR:
    if (trans->state != 0)
      return TWOPENCE_RECEIVE_RESULTS_ERROR;
    if (__twopence_pipe_write(handle, TWOPENCE_STDERR, &payload) < 0)
      return TWOPENCE_RECEIVE_RESULTS_ERROR;
    break;

  case TWOPENCE_PROTO_TYPE_TIMEOUT:
    if (trans->state != 0)
      return TWOPENCE_RECEIVE_RESULTS_ERROR;
    return TWOPENCE_COMMAND_TIMEOUT_ERROR;

  case TWOPENCE_PROTO_TYPE_MAJOR:
    if (trans->state != 0
     || !twopence_protocol_dissect_int(&payload, &trans->status.major))
      return TWOPENCE_RECEIVE_RESULTS_ERROR;
    trans->state = 1;
    break;

  case TWOPENCE_PROTO_TYPE_MINOR:
    if (trans->state != 1
     || !twopence_protocol_dissect_int(&payload, &trans->status.minor))
      return TWOPENCE_RECEIVE_RESULTS_ERROR;
    trans->state = 2;
	trans->done = true;
    break;

  default:
    return TWOPENCE_RECEIVE_RESULTS_ERROR;
  }
  return 0;
}

static int
_twopence_read_results(struct twopence_pipe_target *handle, twopence_status_t *status_ret)
{
  twopence_pipe_transaction_t trans;
  twopence_iostream_t *stream;
  int rc = 0;

  /* Read from the source fd specified by the caller. Can be stdin, can be
   * any other file, or can be negative (meaning no stdin) */
  stream = twopence_target_stream(&handle->base, TWOPENCE_STDIN);

  /* If there is no stdin attached to this command, send an EOF packet
   * to the other end right away (normally, this is sent after we reach
   * EOF on the input.
   */
  if (stream == NULL || twopence_iostream_eof(stream)) {
    /* Send an EOF packet to the server */
    if (__twopence_pipe_send_eof(handle) < 0)
      return TWOPENCE_FORWARD_INPUT_ERROR;
    stream = NULL;
  }

  twopence_pipe_transaction_init(&trans, stream);
  trans.process_packet = __twopence_pipe_command_process_packet;

  while (!trans.done) {
    rc = __twopence_pipe_recvbuf_both(handle, &trans);
    if (rc < 0)
      break;
  }

  *status_ret = trans.status;

  twopence_pipe_transaction_destroy(&trans);
  return rc;
}

// Read major/minor error codes
//
// Returns 0 if everything went fine, or a negative error code if failed
static int
__twopence_wait_status_packet(struct twopence_pipe_target *handle, unsigned int packet_type, int *status_word)
{
  twopence_buf_t *bp, payload;
  const twopence_hdr_t *hdr;
  int rc = TWOPENCE_PROTOCOL_ERROR;

  // Receive a chunk of data
  bp = __twopence_pipe_read_packet(handle);
  if (bp == NULL)
    return TWOPENCE_PROTOCOL_ERROR;

  if ((hdr = twopence_protocol_dissect(bp, &payload)) != NULL
   && hdr->type == packet_type
   && twopence_protocol_dissect_int(&payload, status_word))
    rc = 0;

  twopence_buf_free(bp);
  return rc;
}

static int
_twopence_read_major(struct twopence_pipe_target *handle, int link_fd, int *major)
{
  return __twopence_wait_status_packet(handle, TWOPENCE_PROTO_TYPE_MAJOR, major);
}

// Read minor error code
//
// Returns 0 if everything went fine, or a negative error code if failed
static int
_twopence_read_minor(struct twopence_pipe_target *handle, int link_fd, int *minor)
{
  return __twopence_wait_status_packet(handle, TWOPENCE_PROTO_TYPE_MINOR, minor);
}

// Send a file in chunks to the link; iostream version
//
// Returns 0 if everything went fine, or a negative error code if failed
int _twopence_send_file_iostream
  (struct twopence_pipe_target *handle, twopence_iostream_t *file_stream, int link_fd)
{
  int received, rv = 0;
  int total = 0;

  do {
    twopence_buf_t *bp;

    /* Allocate a new packet with room reserved for the header */
    bp = twopence_protocol_command_buffer_new();

    received = twopence_iostream_read(file_stream,
		    twopence_buf_tail(bp),
		    twopence_buf_tailroom(bp));
    if (received < 0) {
      twopence_buf_free(bp);
      if (errno == EINTR)
	continue;
      goto local_file_error;
    }

    if (received == 0) {
      // Send an EOF packet to the remote host
      twopence_buf_free(bp);
      rv = __twopence_pipe_send_eof(handle);
      break;
    }

    twopence_buf_advance_tail(bp, received);
    twopence_protocol_push_header(bp, TWOPENCE_PROTO_TYPE_DATA);
    if (__twopence_pipe_send(handle, bp) < 0)
      goto send_file_error;

    __twopence_pipe_output(handle, '.');     // Progression dots
    total += received;
  } while (received != 0);

out:
  if (total)
    __twopence_pipe_output(handle, '\n');
  return rv;

local_file_error:
  rv = TWOPENCE_LOCAL_FILE_ERROR;
  goto out;

send_file_error:
  rv = TWOPENCE_SEND_FILE_ERROR;
  goto out;
}

// Receive a file in chunks from the link and write it to a file
//
// Returns 0 if everything went fine, or a negative error code if failed
int _twopence_receive_file
  (struct twopence_pipe_target *handle, twopence_iostream_t *local_stream, int link_fd, int *remote_rc)
{
  int rv = 0;
  twopence_buf_t *bp = NULL;
  int total = 0;

  while (true) {
    const twopence_hdr_t *hdr;
    twopence_buf_t payload;

    if (bp)
      twopence_buf_free(bp);

    bp = __twopence_pipe_read_packet(handle);
    if (bp == NULL)
      goto recv_file_error;

    hdr = twopence_protocol_dissect(bp, &payload);
    if (hdr == NULL)
      goto recv_file_error;

    switch (hdr->type) {
    case TWOPENCE_PROTO_TYPE_MAJOR:
      /* Remote error occurred, usually when trying to open the file */
      (void) twopence_protocol_dissect_int(&payload, remote_rc);
      goto recv_file_error;

    case TWOPENCE_PROTO_TYPE_EOF:
      /* End of data */
      goto out;

    case TWOPENCE_PROTO_TYPE_DATA:
      /* Write data to the file */
      if (__twopence_pipe_write_stream(local_stream, &payload) < 0)
        goto local_file_error;
      total += twopence_buf_count(&payload);
      __twopence_pipe_output(handle, '.');   // Progression dots
      break;

    default:
      goto recv_file_error;
    }
  }

out:
  if (total)
    __twopence_pipe_output(handle, '\n');
  if (bp)
    twopence_buf_free(bp);
  return rv;

recv_file_error:
  rv = TWOPENCE_RECEIVE_FILE_ERROR;
  goto out;

local_file_error:
  rv = TWOPENCE_LOCAL_FILE_ERROR;
  goto out;
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
  twopence_buf_t *bp;
  int rc;
  int was_blocking = -1;

  // By default, no major and no minor
  memset(status_ret, 0, sizeof(*status_ret));

  // Check that the username is valid
  if (_twopence_invalid_username(username))
    return TWOPENCE_PARAMETER_ERROR;

  // Refuse to execute empty commands
  if (*linux_command == '\0')
    return TWOPENCE_PARAMETER_ERROR;

  // Tune input so it is nonblocking
  was_blocking = twopence_target_set_blocking(&handle->base, TWOPENCE_STDIN, false);
  if (was_blocking < 0)
    return TWOPENCE_OPEN_SESSION_ERROR;

  // Open communication link
  if (__twopence_pipe_open_link(handle) < 0) {
    twopence_target_set_blocking(&handle->base, TWOPENCE_STDIN, was_blocking);
    return TWOPENCE_OPEN_SESSION_ERROR;
  }

  // Prepare command to send to the remote host
  bp = twopence_protocol_build_command_packet(username, linux_command, timeout);
  if (bp == NULL)
    return TWOPENCE_PARAMETER_ERROR;

  // Send command
  if (__twopence_pipe_send(handle, bp) < 0) {
    twopence_target_set_blocking(&handle->base, TWOPENCE_STDIN, was_blocking);
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

  // Read "standard output" and "standard error"
  rc = _twopence_read_results(handle, status_ret);
  if (rc < 0)
  {
    twopence_target_set_blocking(&handle->base, TWOPENCE_STDIN, was_blocking);
    return rc;
  }

  /* FIXME: we should really reset the sink on all exit paths from this function */
  twopence_target_set_blocking(&handle->base, TWOPENCE_STDIN, was_blocking);
  return 0;
}

// Inject a file into the remote host
//
// Returns 0 if everything went fine
int __twopence_pipe_inject_file
  (struct twopence_pipe_target *handle, twopence_file_xfer_t *xfer, twopence_status_t *status)
{
  twopence_buf_t *bp;
  int link_fd;
  int rc;

  // Check that the username is valid
  if (_twopence_invalid_username(xfer->user))
    return TWOPENCE_PARAMETER_ERROR;

  // Open communication link
  link_fd = __twopence_pipe_open_link(handle);
  if (link_fd < 0)
    return TWOPENCE_OPEN_SESSION_ERROR;

  // Prepare command to send to the remote host
  bp = twopence_protocol_build_inject_packet(xfer->user, xfer->remote.name, xfer->remote.mode);

  // Send command
  if (__twopence_pipe_send(handle, bp) < 0)
    return TWOPENCE_SEND_COMMAND_ERROR;

  // Read first return code before we start transferring the file
  // This enables to detect a remote problem even before we start the transfer
  rc = _twopence_read_major(handle, link_fd, &status->major);
  if (rc < 0)
    return rc;
  if (status->major != 0)
    return TWOPENCE_SEND_FILE_ERROR;

  // Send the file
  rc = _twopence_send_file_iostream(handle, xfer->local_stream, link_fd);
  if (rc < 0)
    return TWOPENCE_SEND_FILE_ERROR;

  // Read second return code from remote
  rc = _twopence_read_minor(handle, link_fd, &status->minor);
  if (rc < 0)
  {
    return TWOPENCE_SEND_FILE_ERROR;
  }

  return 0;
}

// Extract a file from the remote host
//
// Returns 0 if everything went fine, or a negative error code if failed
int _twopence_extract_virtio_serial
  (struct twopence_pipe_target *handle, twopence_file_xfer_t *xfer, twopence_status_t *status)
{
  twopence_buf_t *bp;
  int link_fd;
  int rc;

  // Check that the username is valid
  if (_twopence_invalid_username(xfer->user))
    return TWOPENCE_PARAMETER_ERROR;

  // Open link for transmitting the command
  link_fd = __twopence_pipe_open_link(handle);
  if (link_fd < 0)
    return TWOPENCE_OPEN_SESSION_ERROR;

  // Prepare command to send to the remote host
  bp = twopence_protocol_build_extract_packet(xfer->user, xfer->remote.name);

  // Send command (including terminating NUL)
  if (__twopence_pipe_send(handle, bp) < 0)
    return TWOPENCE_SEND_COMMAND_ERROR;

  rc = _twopence_receive_file(handle, xfer->local_stream, link_fd, &status->major);
  if (rc < 0)
    return TWOPENCE_RECEIVE_FILE_ERROR;

  return 0;
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
  // Open link for sending interrupt command
  if (__twopence_pipe_open_link(handle) < 0)
    return TWOPENCE_OPEN_SESSION_ERROR;

  // Send command
  if (__twopence_pipe_send(handle, twopence_protocol_build_simple_packet(TWOPENCE_PROTO_TYPE_INTR)) < 0)
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

  if (handle->link_fd >= 0) {
    close(handle->link_fd);
    handle->link_fd = -1;
  }

  free(handle);
}
