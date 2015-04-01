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

// Store length of data chunk to send
static void
store_length(unsigned int length, char *buffer)
{
  buffer[2] = (length & 0xFF00) >> 8;
  buffer[3] = length & 0xFF;
}

// Compute length of data chunk received
static inline unsigned int
compute_length(const void *data)
{
  const unsigned char *cp = (const unsigned char *) data;

  return (cp[2] << 8) | cp[3];
}

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
__twopence_pipe_write(struct twopence_pipe_target *handle, twopence_iofd_t dst, const char *data, size_t len)
{
  return twopence_target_write(&handle->base, dst, data, len);
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
 * Read a chunk (normally called a packet or frame) from the link
 */
static int
__twopence_pipe_read_frame(struct twopence_pipe_target *handle, int link_fd, char *buffer, size_t size)
{
  int rc, length;

  /* First try to read the header */
  rc = __twopence_pipe_recvbuf(handle, link_fd, buffer, 4);
  if (rc < 0)
    return rc;

  length = compute_length(buffer);     // Decode the announced amount of data
  if (length > size)
    return TWOPENCE_PROTOCOL_ERROR;

  /* SECURITY: prevent buffer overflow */
  if (length < 4)
    return TWOPENCE_PROTOCOL_ERROR;

  /* Read the announced amount of data */
  rc = __twopence_pipe_recvbuf(handle, link_fd, buffer + 4, length - 4);
  if (rc < 0)
    return rc;

  return 0;
}


/*
 * Helper function to read from either link or stdin
 */
static int
__twopence_pipe_recvbuf_both(struct twopence_pipe_target *handle, int link_fd, twopence_iostream_t *stdin_stream, char *buffer, size_t size)
{
  unsigned long timeout = handle->link_timeout;

  while (true) {
    struct pollfd pfd[2];
    int nfds = 0, n;
    int count;

    pfd[nfds].fd = link_fd;
    pfd[nfds].events = POLLIN;
    nfds++;

    if (stdin_stream && !twopence_iostream_eof(stdin_stream)) {
      n = twopence_iostream_poll(stdin_stream, &pfd[nfds], POLLIN);
      if (n == 0) {
	/* A zero return code indicates the stream does not support polling,
	 * which is the case of a buffer for instance.
	 * Try to read from it directly.
	 */
        count = twopence_iostream_read(stdin_stream, buffer + 4, size - 4);
	if (count >= 0)
	  goto process_stdin;
      }
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
      return __twopence_pipe_read_frame(handle, link_fd, buffer, size);
    }

    if (nfds > 1 && (pfd[1].revents & (POLLIN|POLLHUP))) {
      count = twopence_iostream_read(stdin_stream, buffer + 4, size - 4);
      if (count < 0) {
	if (errno == EINTR)
	  continue;
	return count;
      }

process_stdin:
      if (count == 0) {
        buffer[0] = 'E'; /* EOF on standard input */
      } else {
	buffer[0] = '0'; /* Data on standard input */
      }

      store_length(count + 4, buffer);
      return count + 4;
    }

    /* Can we get here? */
  }

  return 0;
}

///////////////////////////// Middle layer //////////////////////////////////////
// Read stdin, stdout, stderr, and both error codes
//
// Returns 0 if everything went fine, or a negative error code if failed
static int
_twopence_read_results(struct twopence_pipe_target *handle, int link_fd, twopence_status_t *status_ret)
{
  int state;                           // 0 = processing results, 1 = major received, 2 = minor received
  twopence_iostream_t *stream;
  char buffer[BUFFER_SIZE];
  int received, sent;

  /* Read from the source fd specified by the caller. Can be stdin, can be
   * any other file, or can be negative (meaning no stdin) */
  stream = twopence_target_stream(&handle->base, TWOPENCE_STDIN);

  /* If there is no stdin attached to this command, send an EOF packet
   * to the other end right away (normally, this is sent after we reach
   * EOF on the input.
   */
  if (stream == NULL || twopence_iostream_eof(stream)) {
    /* Send an EOF packet to the server */
    buffer[0] = 'E';
    store_length(4, buffer);
    sent = __twopence_pipe_sendbuf(handle, link_fd, buffer, 4);
    if (sent < 0)
      return TWOPENCE_FORWARD_INPUT_ERROR;
  }

  state = 0;

  while (state != 2)
  {
    if (__twopence_pipe_recvbuf_both
            (handle, link_fd, stream, buffer, sizeof(buffer)) < 0)
      return TWOPENCE_RECEIVE_RESULTS_ERROR;

    received = compute_length(buffer);
    switch (buffer[0]) {
      case 'E':                        // End of file on stdin
	twopence_iostream_destroy(stream);
	stream = NULL;
	/* fallthru */
      case '0':                        // Data on stdin
        if (state != 0)
          return TWOPENCE_FORWARD_INPUT_ERROR;
	// Forward it to the system under test
        sent = __twopence_pipe_sendbuf(handle, link_fd, buffer, received);
        if (sent < 0)
          return TWOPENCE_FORWARD_INPUT_ERROR;
        break;

      case '1':                        // stdout
        if (state != 0)
          return TWOPENCE_RECEIVE_RESULTS_ERROR;
	if (__twopence_pipe_write(handle, TWOPENCE_STDOUT, buffer + 4, received - 4) < 0)
          return TWOPENCE_RECEIVE_RESULTS_ERROR;
        break;

      case '2':                        // stderr
        if (state != 0)
          return TWOPENCE_RECEIVE_RESULTS_ERROR;
	if (__twopence_pipe_write(handle, TWOPENCE_STDERR, buffer + 4, received - 4) < 0)
          return TWOPENCE_RECEIVE_RESULTS_ERROR;
        break;

      case 'T':                        // Command timeout
        if (state != 0)
          return TWOPENCE_RECEIVE_RESULTS_ERROR;
        return TWOPENCE_COMMAND_TIMEOUT_ERROR;

      case 'M':                        // Major error code
        if (state != 0)
          return TWOPENCE_RECEIVE_RESULTS_ERROR;
        state = 1;
        sscanf(buffer + 4, "%d", &status_ret->major);
        break;

      case 'm':                        // Minor error code
        if (state != 1)
          return TWOPENCE_RECEIVE_RESULTS_ERROR;
        state = 2;
        sscanf(buffer + 4, "%d", &status_ret->minor);
        break;

      default:
        return TWOPENCE_RECEIVE_RESULTS_ERROR;
    }
  }

  return 0;
}

// Read major error code
//
// Returns 0 if everything went fine, or a negative error code if failed
static int
_twopence_read_major(struct twopence_pipe_target *handle, int link_fd, int *major)
{
  char buffer[BUFFER_SIZE];
  int rc;

  // Receive a chunk of data
  rc = __twopence_pipe_read_frame(handle, link_fd, buffer, sizeof(buffer));
  if (rc != 0)
    return TWOPENCE_RECEIVE_FILE_ERROR;

  if (buffer[0] != 'M')                // Analyze the header
    return TWOPENCE_RECEIVE_FILE_ERROR;
  sscanf(buffer + 4, "%d", major);

  return 0;
}

// Read minor error code
//
// Returns 0 if everything went fine, or a negative error code if failed
static int
_twopence_read_minor(struct twopence_pipe_target *handle, int link_fd, int *minor)
{
  char buffer[BUFFER_SIZE];
  int rc;

  // Receive a chunk of data
  rc = __twopence_pipe_read_frame(handle, link_fd, buffer, sizeof(buffer));
  if (rc != 0)
    return TWOPENCE_RECEIVE_FILE_ERROR;

  if (buffer[0] != 'm')                // Analyze the header
    return TWOPENCE_RECEIVE_FILE_ERROR;
  sscanf(buffer + 4, "%d", minor);

  return 0;
}

// Send a file in chunks to the link; iostream version
//
// Returns 0 if everything went fine, or a negative error code if failed
int _twopence_send_file_iostream
  (struct twopence_pipe_target *handle, twopence_iostream_t *file_stream, int link_fd)
{
  char buffer[BUFFER_SIZE];
  int received, rv = 0;
  int total = 0;

  buffer[1] = '\0';

  do {
    received = twopence_iostream_read(file_stream, buffer + 4, BUFFER_SIZE - 4);
    if (received < 0) {
      if (errno == EINTR)
	continue;
      goto local_file_error;
    }
    if (received == 0) {
      // Send an EOF packet to the remote host
      buffer[0] = 'E';
    } else {
      // Send data to the remote host, together with 4 bytes of header
      buffer[0] = 'd';
    }
    store_length(received + 4, buffer);

    if (!__twopence_pipe_sendbuf(handle, link_fd, buffer, received + 4))
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

// Send a file in chunks to the link
//
// Returns 0 if everything went fine, or a negative error code if failed
int _twopence_send_file
  (struct twopence_pipe_target *handle, int file_fd, int link_fd)
{
  twopence_iostream_t *file_stream;
  int rc;

  rc = twopence_iostream_wrap_fd(file_fd, false, &file_stream);
  if (rc < 0)
    return TWOPENCE_LOCAL_FILE_ERROR;

  rc = _twopence_send_file_iostream(handle, file_stream, link_fd);
  twopence_iostream_free(file_stream);
  return rc;
}

// Receive a file in chunks from the link and write it to a file
//
// Returns 0 if everything went fine, or a negative error code if failed
int _twopence_receive_file
  (struct twopence_pipe_target *handle, twopence_iostream_t *local_stream, int link_fd, int *remote_rc)
{
  char buffer[BUFFER_SIZE];
  int rc, received, written, rv = 0;
  int total = 0;

  while (true)
  {
    rc = __twopence_pipe_read_frame(handle, link_fd, buffer, sizeof(buffer));
    if (rc != 0)
      goto recv_file_error;

    received = compute_length(buffer) - 4;
    switch (buffer[0]) {
    case 'M':
      /* Remote error occurred, usually when trying to open the file */
      sscanf(buffer + 4, "%d", remote_rc);
      goto recv_file_error;

    case 'E':
      /* End of data */
      goto out;

    case 'd':
      /* Write data to the file */
      written = twopence_iostream_write(local_stream, buffer + 4, received);
      if (written != received)
        goto local_file_error;
      __twopence_pipe_output(handle, '.');   // Progression dots
      total += received;
      break;
    default:
      goto recv_file_error;
    }
  }

out:
  if (total)
    __twopence_pipe_output(handle, '\n');
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
  char command[COMMAND_BUFFER_SIZE];
  int n;
  int link_fd = -1;
  int sent, rc;
  int was_blocking = -1;

  // By default, no major and no minor
  memset(status_ret, 0, sizeof(*status_ret));

  // Check that the username is valid
  if (_twopence_invalid_username(username))
    return TWOPENCE_PARAMETER_ERROR;

  // Refuse to execute empty commands
  if (*linux_command == '\0')
    return TWOPENCE_PARAMETER_ERROR;

  // Prepare command to send to the remote host
  n = snprintf(command, COMMAND_BUFFER_SIZE,
               "c...%s %ld %s", username, timeout, linux_command);
  if (n < 0 || n >= COMMAND_BUFFER_SIZE)
    return TWOPENCE_PARAMETER_ERROR;
  store_length(n + 1, command);

  // Tune input so it is nonblocking
  was_blocking = twopence_target_set_blocking(&handle->base, TWOPENCE_STDIN, false);
  if (was_blocking < 0)
    return TWOPENCE_OPEN_SESSION_ERROR;

  // Open communication link
  link_fd = __twopence_pipe_open_link(handle);
  if (link_fd < 0)
  {
    twopence_target_set_blocking(&handle->base, TWOPENCE_STDIN, was_blocking);
    return TWOPENCE_OPEN_SESSION_ERROR;
  }

  // Send command (including terminating NUL)
  sent = __twopence_pipe_sendbuf(handle, link_fd, command, n + 1);
  if (sent != n + 1)
  {
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
  rc = _twopence_read_results(handle, link_fd, status_ret);
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
  char command[COMMAND_BUFFER_SIZE];
  int n;
  int link_fd;
  int sent, rc;

  // Check that the username is valid
  if (_twopence_invalid_username(xfer->user))
    return TWOPENCE_PARAMETER_ERROR;

  // Prepare command to send to the remote host
  n = snprintf(command, COMMAND_BUFFER_SIZE,
               "i...%s %d %s", xfer->user, xfer->remote.mode, xfer->remote.name);
  if (n < 0 || n >= COMMAND_BUFFER_SIZE)
    return TWOPENCE_PARAMETER_ERROR;
  store_length(n + 1, command);

  // Open communication link
  link_fd = __twopence_pipe_open_link(handle);
  if (link_fd < 0)
    return TWOPENCE_OPEN_SESSION_ERROR;

  // Send command (including terminating NUL)
  sent = __twopence_pipe_sendbuf(handle, link_fd, command, n + 1);
  if (sent != n + 1)
  {
    return TWOPENCE_SEND_COMMAND_ERROR;
  }

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
  {
    return TWOPENCE_SEND_FILE_ERROR;
  }

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
  char command[COMMAND_BUFFER_SIZE];
  int n;
  int link_fd;
  int sent, rc;

  // Check that the username is valid
  if (_twopence_invalid_username(xfer->user))
    return TWOPENCE_PARAMETER_ERROR;

  // Prepare command to send to the remote host
  n = snprintf(command, COMMAND_BUFFER_SIZE,
               "e...%s %s", xfer->user, xfer->remote.name);
  if (n < 0 || n >= COMMAND_BUFFER_SIZE)
    return TWOPENCE_PARAMETER_ERROR;
  store_length(n + 1, command);

  // Open link for transmitting the command
  link_fd = __twopence_pipe_open_link(handle);
  if (link_fd < 0)
    return TWOPENCE_OPEN_SESSION_ERROR;

  // Send command (including terminating NUL)
  sent = __twopence_pipe_sendbuf(handle, link_fd, command, n + 1);
  if (sent != n + 1)
  {
    return TWOPENCE_SEND_COMMAND_ERROR;
  }

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
  char command[COMMAND_BUFFER_SIZE];
  int n;
  int link_fd;
  int sent;

  // Prepare command to send to the remote host
  n = snprintf(command, COMMAND_BUFFER_SIZE,
               "q...");
  if (n < 0 || n >= COMMAND_BUFFER_SIZE)
    return TWOPENCE_PARAMETER_ERROR;
  store_length(n + 1, command);

  // Open link for sending exit command
  link_fd = __twopence_pipe_open_link(handle);
  if (link_fd < 0)
    return TWOPENCE_OPEN_SESSION_ERROR;

  // Send command (including terminating NUL)
  sent = __twopence_pipe_sendbuf(handle, link_fd, command, n + 1);
  if (sent != n + 1)
  {
    return TWOPENCE_SEND_COMMAND_ERROR;
  }

  return 0;
}

// Interrupt current command
//
// Returns 0 if everything went fine, or a negative error code if failed
int _twopence_interrupt_virtio_serial
  (struct twopence_pipe_target *handle)
{
  char command[COMMAND_BUFFER_SIZE];
  int n;
  int link_fd;
  int sent;

  // Prepare command to send to the remote host
  n = snprintf(command, COMMAND_BUFFER_SIZE,
               "I...");
  if (n < 0 || n >= COMMAND_BUFFER_SIZE)
    return TWOPENCE_PARAMETER_ERROR;
  store_length(n + 1, command);

  // Open link for sending interrupt command
  link_fd = __twopence_pipe_open_link(handle);
  if (link_fd < 0)
    return TWOPENCE_OPEN_SESSION_ERROR;

  // Send command (including terminating NUL)
  sent = __twopence_pipe_sendbuf(handle, link_fd, command, n + 1);
  if (sent != n + 1)
  {
    return TWOPENCE_INTERRUPT_COMMAND_ERROR;
  }

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
