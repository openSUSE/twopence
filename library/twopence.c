/*
Based on the utility routines for Twopence.

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

#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/poll.h>

#include "twopence.h"


static void	__twopence_setup_stdout(struct twopence_target *target);


int
twopence_plugin_type(const char *plugin_name)
{
  if (!strcmp(plugin_name, "virtio"))
    return TWOPENCE_PLUGIN_VIRTIO;
  if (!strcmp(plugin_name, "ssh"))
    return TWOPENCE_PLUGIN_SSH;
  if (!strcmp(plugin_name, "serial"))
    return TWOPENCE_PLUGIN_SERIAL;

  return TWOPENCE_PLUGIN_UNKNOWN;
}

bool
twopence_plugin_name_is_valid(const char *name)
{
  /* For the time being, we only recognize built-in plugin names.
   * That is not really the point of a pluggable architecture, though -
   * it's supposed to allow plugging in functionality that we weren't
   * aware of at originally...
   * Well, whatever :-)
   */
  return twopence_plugin_type(name) != TWOPENCE_PLUGIN_UNKNOWN;
}

/*
 * Split the target, which is of the form "plugin:specstring" into its
 * two components.
 */
static char *
twopence_target_split(char **target_spec_p)
{
  char *plugin;
  unsigned int len;

  if (target_spec_p == NULL || (plugin = *target_spec_p) == NULL)
    return NULL;

  len = strcspn(plugin, ":");
  if (len == 0)
    return NULL;

  /* NUL terminate the plugin string */
  if (plugin[len] != '\0') {
    plugin[len++] = '\0';
    *target_spec_p = plugin + len;
  } else {
    *target_spec_p = NULL;
  }

  if (!twopence_plugin_name_is_valid(plugin))
    return NULL;

  return plugin;
}

static int
__twopence_get_plugin_ops(const char *name, const struct twopence_plugin **ret)
{
  static const struct twopence_plugin *plugins[__TWOPENCE_PLUGIN_MAX] = {
  [TWOPENCE_PLUGIN_VIRTIO]	= &twopence_virtio_ops,
  [TWOPENCE_PLUGIN_SERIAL]	= &twopence_serial_ops,
  [TWOPENCE_PLUGIN_SSH]		= &twopence_ssh_ops,
  };
  int type;

  type = twopence_plugin_type(name);
  if (type < 0 || type >= __TWOPENCE_PLUGIN_MAX)
    return TWOPENCE_UNKNOWN_PLUGIN_ERROR;

  *ret = plugins[type];
  if (*ret == NULL)
    return TWOPENCE_UNKNOWN_PLUGIN_ERROR;

  return 0;
}

static int
__twopence_target_new(char *target_spec, struct twopence_target **ret)
{
  const struct twopence_plugin *plugin;
  struct twopence_target *target;
  char *name;
  int rc;

  name = twopence_target_split(&target_spec);
  if (name == NULL)
    return TWOPENCE_INVALID_TARGET_ERROR;

  rc = __twopence_get_plugin_ops(name, &plugin);
  if (rc < 0)
    return rc;

  /* FIXME: check a version number provided by the plugin data */

  if (plugin->init == NULL)
    return TWOPENCE_INCOMPATIBLE_PLUGIN_ERROR;

  /* Create the handle */
  target = plugin->init(target_spec);
  if (target == NULL)
    return TWOPENCE_UNKNOWN_PLUGIN_ERROR;

  *ret = target;
  return 0;
}

int
twopence_target_new(const char *target_spec, struct twopence_target **ret)
{
  char *spec_copy;
  int rv;

  spec_copy = strdup(target_spec);
  rv = __twopence_target_new(spec_copy, ret);
  free(spec_copy);

  return rv;
}

void
twopence_target_free(struct twopence_target *target)
{
  if (target->ops->end == NULL) {
    free(target);
  } else {
    target->ops->end(target);
  }
}

/*
 * target level output functions
 */
twopence_iostream_t *
twopence_target_stream(struct twopence_target *target, twopence_iofd_t dst)
{
  if (0 <= dst && dst < __TWOPENCE_IO_MAX
   && target->current.io != NULL)
    return &target->current.io[dst];

  return NULL;
}

int
twopence_target_set_blocking(struct twopence_target *target, twopence_iofd_t sel, bool blocking)
{
  twopence_iostream_t *stream;

  if ((stream = twopence_target_stream(target, sel)) == NULL)
    return -1;

  return twopence_iostream_set_blocking(stream, blocking);
}

int
twopence_target_putc(struct twopence_target *target, twopence_iofd_t dst, char c)
{
  twopence_iostream_t *stream;

  if ((stream = twopence_target_stream(target, dst)) == NULL)
    return -1;

  return twopence_iostream_putc(stream, c);
}

int
twopence_target_write(struct twopence_target *target, twopence_iofd_t dst, const char *data, size_t len)
{
  twopence_iostream_t *stream;

  if ((stream = twopence_target_stream(target, dst)) == NULL)
    return -1;

  return twopence_iostream_write(stream, data, len);
}

/*
 * General API
 */
int
twopence_run_test(struct twopence_target *target, twopence_command_t *cmd, twopence_status_t *status)
{
  if (target->ops->run_test == NULL)
    return TWOPENCE_UNSUPPORTED_FUNCTION_ERROR;

  target->current.io = NULL;

  /* Populate defaults. Instead of hard-coding them, we could also set
   * default values for a given target. */
  if (cmd->timeout == 0)
    cmd->timeout = 60;
  if (cmd->user == NULL)
    cmd->user = "root";

  return target->ops->run_test(target, cmd, status);
}

int
twopence_test_and_print_results
  (struct twopence_target *target, const char *username, long timeout, const char *command, twopence_status_t *status)
{
  if (target->ops->run_test) {
    twopence_command_t cmd;

    twopence_command_init(&cmd, command);
    cmd.user = username;
    cmd.timeout = timeout;

    twopence_command_ostreams_reset(&cmd);
    twopence_command_iostream_redirect(&cmd, TWOPENCE_STDIN, 0, false);
    twopence_command_iostream_redirect(&cmd, TWOPENCE_STDOUT, 1, false);
    twopence_command_iostream_redirect(&cmd, TWOPENCE_STDERR, 2, false);

    return twopence_run_test(target, &cmd, status);
  }

  return TWOPENCE_UNSUPPORTED_FUNCTION_ERROR;
}

int
twopence_test_and_drop_results
  (struct twopence_target *target, const char *username, long timeout, const char *command, twopence_status_t *status)
{
  if (target->ops->run_test) {
    twopence_command_t cmd;

    twopence_command_init(&cmd, command);
    cmd.user = username;
    cmd.timeout = timeout;

    /* Reset both ostreams to nothing */
    twopence_command_ostreams_reset(&cmd);
    twopence_command_iostream_redirect(&cmd, TWOPENCE_STDIN, 0, false);

    return twopence_run_test(target, &cmd, status);
  }

  return TWOPENCE_UNSUPPORTED_FUNCTION_ERROR;
}

int
twopence_test_and_store_results_together
  (struct twopence_target *target, const char *username, long timeout, const char *command,
   twopence_buffer_t *buffer, twopence_status_t *status)
{
  if (target->ops->run_test) {
    twopence_command_t cmd;

    twopence_command_init(&cmd, command);
    cmd.user = username;
    cmd.timeout = timeout;

    twopence_command_ostreams_reset(&cmd);
    twopence_command_iostream_redirect(&cmd, TWOPENCE_STDIN, 0, false);
    if (buffer) {
      twopence_command_ostream_capture(&cmd, TWOPENCE_STDOUT, buffer);
      twopence_command_ostream_capture(&cmd, TWOPENCE_STDERR, buffer);
    }

    return twopence_run_test(target, &cmd, status);
  }

  return TWOPENCE_UNSUPPORTED_FUNCTION_ERROR;
}

int
twopence_test_and_store_results_separately
  (struct twopence_target *target, const char *username, long timeout, const char *command,
   twopence_buffer_t *stdout_buffer, twopence_buffer_t *stderr_buffer, twopence_status_t *status)
{
  if (target->ops->run_test) {
    twopence_command_t cmd;

    twopence_command_init(&cmd, command);
    cmd.user = username;
    cmd.timeout = timeout;

    twopence_command_ostreams_reset(&cmd);
    twopence_command_iostream_redirect(&cmd, TWOPENCE_STDIN, 0, false);
    if (stdout_buffer)
      twopence_command_ostream_capture(&cmd, TWOPENCE_STDOUT, stdout_buffer);
    if (stderr_buffer)
      twopence_command_ostream_capture(&cmd, TWOPENCE_STDERR, stderr_buffer);

    return twopence_run_test(target, &cmd, status);
  }

  return TWOPENCE_UNSUPPORTED_FUNCTION_ERROR;
}

int
twopence_inject_file
  (struct twopence_target *target, const char *username,
   const char *local_path, const char *remote_path,
   int *remote_rc, bool print_dots)
{
  if (target->ops->inject_file == NULL)
    return TWOPENCE_UNSUPPORTED_FUNCTION_ERROR;

  /* Reset output, and connect with stdout if we want to see the dots get printed */
  target->current.io = NULL;
  if (print_dots)
    __twopence_setup_stdout(target);

  return target->ops->inject_file(target, username, local_path, remote_path, remote_rc, print_dots);
}

int
twopence_extract_file
  (struct twopence_target *target, const char *username,
   const char *remote_path, const char *local_path,
   int *remote_rc, bool print_dots)
{
  if (target->ops->extract_file == NULL)
    return TWOPENCE_UNSUPPORTED_FUNCTION_ERROR;

  /* Reset output, and connect with stdout if we want to see the dots get printed */
  target->current.io = NULL;
  if (print_dots)
    __twopence_setup_stdout(target);

  return target->ops->extract_file(target, username, remote_path, local_path, remote_rc, print_dots);
}

int
twopence_exit_remote(struct twopence_target *target)
{
  if (target->ops->exit_remote == NULL)
    return TWOPENCE_UNSUPPORTED_FUNCTION_ERROR;

  return target->ops->exit_remote(target);
}

int
twopence_interrupt_command(struct twopence_target *target)
{
  if (target->ops->interrupt_command == NULL)
    return TWOPENCE_UNSUPPORTED_FUNCTION_ERROR;

  return target->ops->interrupt_command(target);
}


/*
 * Convert twopence error code to string message
 */
const char *
twopence_strerror(int rc)
{
  switch (rc) {
    case TWOPENCE_PARAMETER_ERROR:
      return "Invalid command parameter";
    case TWOPENCE_OPEN_SESSION_ERROR:
      return "Error opening the communication with the system under test";
    case TWOPENCE_SEND_COMMAND_ERROR:
      return "Error sending command to the system under test";
    case TWOPENCE_FORWARD_INPUT_ERROR:
      return "Error forwarding keyboard input";
    case TWOPENCE_RECEIVE_RESULTS_ERROR:
      return "Error receiving the results of action";
    case TWOPENCE_COMMAND_TIMEOUT_ERROR:
      return "Remote command took too long to execute";
    case TWOPENCE_LOCAL_FILE_ERROR:
      return "Local error while transferring file";
    case TWOPENCE_SEND_FILE_ERROR:
      return "Error sending file to the system under test";
    case TWOPENCE_REMOTE_FILE_ERROR:
      return "Remote error while transferring file";
    case TWOPENCE_RECEIVE_FILE_ERROR:
      return "Error receiving file from the system under test";
    case TWOPENCE_INTERRUPT_COMMAND_ERROR:
      return "Failed to interrupt command";
    case TWOPENCE_INVALID_TARGET_ERROR:
      return "Invalid target specification";
    case TWOPENCE_UNKNOWN_PLUGIN_ERROR:
      return "Unknown plugin";
    case TWOPENCE_INCOMPATIBLE_PLUGIN_ERROR:
      return "Incompatible plugin";
    case TWOPENCE_UNSUPPORTED_FUNCTION_ERROR:
      return "Operation not supported by the plugin";
    case TWOPENCE_PROTOCOL_ERROR:
      return "Twopence custom protocol error";
  }
  return "Unknow error";
}

void
twopence_perror(const char *msg, int rc)
{
  fprintf(stderr, "%s: %s.\n", msg, twopence_strerror(rc));
}

/*
 * Handling of command structs
 */
void
twopence_command_init(twopence_command_t *cmd, const char *cmdline)
{
  memset(cmd, 0, sizeof(*cmd));

  /* By default, all output from the remote command is sent to our own
   * stdout and stderr.
   * The input of the remote command is not connected.
   */
  twopence_command_iostream_redirect(cmd, TWOPENCE_STDOUT, 1, false);
  twopence_command_iostream_redirect(cmd, TWOPENCE_STDERR, 2, false);

  cmd->command = cmdline;
}

static inline twopence_buffer_t *
__twopence_command_buffer(twopence_command_t *cmd, twopence_iofd_t dst)
{
  if (0 <= dst && dst < __TWOPENCE_IO_MAX)
    return &cmd->buffer[dst];
  return NULL;
}

twopence_buffer_t *
twopence_command_alloc_buffer(twopence_command_t *cmd, twopence_iofd_t dst, size_t size)
{
  twopence_buffer_t *bp;

  if ((bp = __twopence_command_buffer(cmd, dst)) == NULL)
    return NULL;

  twopence_buffer_free(bp);
  if (size)
    twopence_buffer_alloc(bp, size);
  return bp;
}

static inline twopence_iostream_t *
__twopence_command_ostream(twopence_command_t *cmd, twopence_iofd_t dst)
{
  if (0 <= dst && dst < __TWOPENCE_IO_MAX)
    return &cmd->iostream[dst];
  return NULL;
}

void
twopence_command_ostreams_reset(twopence_command_t *cmd)
{
  unsigned int i;

  for (i = 0; i < __TWOPENCE_IO_MAX; ++i)
    twopence_iostream_destroy(&cmd->iostream[i]);
}

void
twopence_command_ostream_reset(twopence_command_t *cmd, twopence_iofd_t dst)
{
  twopence_iostream_t *stream;

  if ((stream = __twopence_command_ostream(cmd, dst)) != NULL)
    twopence_iostream_destroy(stream);
}

void
twopence_command_ostream_capture(twopence_command_t *cmd, twopence_iofd_t dst, twopence_buffer_t *bp)
{
  twopence_iostream_t *stream;

  if ((stream = __twopence_command_ostream(cmd, dst)) != NULL)
    twopence_iostream_add_substream(stream, twopence_substream_new_buffer(bp));
}

void
twopence_command_iostream_redirect(twopence_command_t *cmd, twopence_iofd_t dst, int fd, bool closeit)
{
  twopence_iostream_t *stream;

  if ((stream = __twopence_command_ostream(cmd, dst)) != NULL)
    twopence_iostream_add_substream(stream, twopence_substream_new_fd(fd, closeit));
}

void
twopence_command_destroy(twopence_command_t *cmd)
{
  unsigned int i;

  for (i = 0; i < __TWOPENCE_IO_MAX; ++i) {
    twopence_buffer_free(&cmd->buffer[i]);
    twopence_iostream_destroy(&cmd->iostream[i]);
  }
}

/*
 * Output handling
 */
static void
__twopence_buffer_init(struct twopence_buffer *buf, char *head, size_t size)
{
  buf->head = buf->tail = head;
  buf->end = head + size;
}

void
twopence_buffer_init(twopence_buffer_t *buf)
{
  memset(buf, 0, sizeof(*buf));
}

void
twopence_buffer_alloc(twopence_buffer_t *buf, size_t size)
{
  __twopence_buffer_init(buf, calloc(size, 1), size);
}

void
twopence_buffer_free(twopence_buffer_t *buf)
{
  if (buf->head)
    free(buf->head);
  memset(buf, 0, sizeof(*buf));
}

/*
 * This is a helper function to set everything up so that inject/extract
 * will print dots while transferring data
 */
static void
__twopence_setup_stdout(struct twopence_target *target)
{
  static twopence_iostream_t dots_iostream[__TWOPENCE_IO_MAX];

  if (dots_iostream[TWOPENCE_STDOUT].count == 0)
    twopence_iostream_add_substream(&dots_iostream[TWOPENCE_STDOUT], twopence_substream_new_fd(1, false));

  target->current.io = dots_iostream;
}


void
twopence_iostream_add_substream(twopence_iostream_t *stream, twopence_substream_t *substream)
{
  if (stream->count >= TWOPENCE_IOSTREAM_MAX_SUBSTREAMS) {
    twopence_substream_close(substream);
    free(substream);
    return;
  }

  stream->substream[stream->count++] = substream;
}

void
twopence_iostream_destroy(twopence_iostream_t *stream)
{
  unsigned int i;

  for (i = 0; i < stream->count; ++i) {
    twopence_substream_t *substream = stream->substream[i];

    twopence_substream_close(substream);
    free(substream);
  }
  memset(stream, 0, sizeof(*stream));
}

/*
 * Buffering functions
 */
static unsigned int
__twopence_buffer_put(struct twopence_buffer *bp, const void *data, size_t len)
{
  size_t tailroom;

  tailroom = bp->end - bp->tail;
  if (len > tailroom)
    len = tailroom;

  memcpy(bp->tail, data, len);
  bp->tail += len;
  return len;
}

/*
 * Check if iostream is at EOF
 */
bool
twopence_iostream_eof(const twopence_iostream_t *stream)
{
  return stream->eof;
}

/*
 * Tune blocking behavior of iostream
 */
int
twopence_iostream_set_blocking(twopence_iostream_t *stream, bool blocking)
{
  int was_blocking = 0;
  unsigned int i;

  if (stream->eof || stream->count == 0)
    return false;

  for (i = 0; i < stream->count; ++i) {
    twopence_substream_t *substream = stream->substream[i];

    if (substream->ops == NULL)
       continue;
    if (substream->ops->set_blocking == NULL)
      return -1;

    was_blocking = substream->ops->set_blocking(substream, blocking);
  }

  return was_blocking;
}

/*
 * Fill a pollfd struct
 * Returns one of:
 *   0 (EOF condition, pfd struct not filled in)
 *   1 (pfd struct valid)
 *  <0 (error)
 */
int
twopence_iostream_poll(twopence_iostream_t *stream, struct pollfd *pfd, int mask)
{
  unsigned int i;

  if (stream->eof || stream->count == 0)
    return 0;

  /* We can only do POLLIN for now */
  if (mask & POLLOUT)
    return -1;

  /* Find the first non-EOF substream and fill in the pollfd */
  for (i = 0; i < stream->count; ++i) {
    twopence_substream_t *substream = stream->substream[i];

    if (substream->ops == NULL)
      continue;

    if (substream->ops->poll == NULL)
      return -1;

    return substream->ops->poll(substream, pfd, mask);
  }

  /* All substreams are EOF, so no polling */
  return 0;
}

/*
 * Read from an iostream
 */
int
twopence_iostream_getc(twopence_iostream_t *stream)
{
  unsigned int i;

  if (stream->eof || stream->count == 0)
    return EOF;

  for (i = 0; i < stream->count; ++i) {
    twopence_substream_t *substream = stream->substream[i];
    unsigned char c;
    int n;

    if (substream->ops == NULL || substream->ops->read == NULL)
      continue;
    n = substream->ops->read(substream, &c, 1);
    if (n == 1)
      return c;

    // This substream is at its EOF
    twopence_substream_close(substream);
  }

  stream->eof = true;
  return 0;
}

int
twopence_iostream_read(twopence_iostream_t *stream, char *data, size_t len)
{
  unsigned int i;

  if (stream->eof || stream->count == 0)
    return 0;

  for (i = 0; i < stream->count; ++i) {
    twopence_substream_t *substream = stream->substream[i];
    int n;

    if (substream->ops == NULL || substream->ops->read == NULL)
      continue;

    n = substream->ops->read(substream, data, len);
    if (n > 0)
      return n;

    if (n < 0)
      return n;

    // This substream is at its EOF
    twopence_substream_close(substream);
  }

  stream->eof = true;
  return 0;
}

/*
 * Write to a sink object
 */
int
twopence_iostream_putc(twopence_iostream_t *stream, char c)
{
  unsigned int i;

  if (stream->count == 0)
    return 0;

  for (i = 0; i < stream->count; ++i) {
    twopence_substream_t *substream = stream->substream[i];

    if (substream->ops == NULL || substream->ops->write == NULL)
      return -1;
    substream->ops->write(substream, &c, 1);
  }

  return 1;
}

int
twopence_iostream_write(twopence_iostream_t *stream, const char *data, size_t len)
{
  unsigned int i;

  if (stream->count == 0)
    return 0;

  for (i = 0; i < stream->count; ++i) {
    twopence_substream_t *substream = stream->substream[i];

    if (substream->ops == NULL || substream->ops->write == NULL)
      return -1;
    substream->ops->write(substream, data, len);
  }

  return len;
}

/*
 * Create a new substream object
 */
static twopence_substream_t *
__twopence_substream_new(const twopence_io_ops_t *ops)
{
  twopence_substream_t *substream;

  substream = calloc(1, sizeof(*substream));
  substream->ops = ops;

  return substream;
}

void
twopence_substream_close(twopence_substream_t *substream)
{
  if (substream->ops == NULL)
    return;

  if (substream->ops->close)
    substream->ops->close(substream);
  substream->ops = NULL;
}

/*
 * Handle a buffered substream
 */
static int
twopence_substream_buffer_write(twopence_substream_t *sink, const void *data, size_t len)
{
  twopence_buffer_t *bp = (twopence_buffer_t *) sink->data;

  __twopence_buffer_put(bp, data, len);
  return len;
}

static int
twopence_substream_buffer_read(twopence_substream_t *src, void *data, size_t len)
{
  return -1; // Not supported for now
}

static twopence_io_ops_t twopence_buffer_io = {
	.read	= twopence_substream_buffer_read,
	.write	= twopence_substream_buffer_write,
};

twopence_substream_t *
twopence_substream_new_buffer(twopence_buffer_t *bp)
{
  twopence_substream_t *io;

  io = __twopence_substream_new(&twopence_buffer_io);
  io->data = bp;
  return io;
}

/*
 * fd based substreams
 */
static void
twopence_substream_file_close(twopence_substream_t *substream)
{
  if (substream->fd >= 0 && substream->close) {
    close(substream->fd);
    substream->fd = -1;
  }
}

static int
twopence_substream_file_write(twopence_substream_t *sink, const void *data, size_t len)
{
  int fd = sink->fd;

  if (fd < 0)
    return -1;

   return write(fd, data, len);
}

static int
twopence_substream_file_read(twopence_substream_t *src, void *data, size_t len)
{
  int fd = src->fd;

  if (fd < 0)
    return -1;

   return read(fd, data, len);
}

int
twopence_substream_file_set_blocking(twopence_substream_t *src, bool blocking)
{
  int oflags, nflags;

  if (src->fd < 0)
    return 0;

  oflags = fcntl(src->fd, F_GETFL);        // Get old flags
  if (oflags == -1)
    return -1;

  nflags = oflags & ~O_NONBLOCK;
  if (!blocking)
    nflags |= O_NONBLOCK;

  if (fcntl(src->fd, F_SETFL, nflags) < 0)
    return -1;

  /* Return old settings (true means it was using blocking mode before the change) */
  return !(oflags & O_NONBLOCK);
}

int
twopence_substream_file_poll(twopence_substream_t *src, struct pollfd *pfd, int mask)
{
  if (src->fd < 0)
    return 0;

  pfd->fd = src->fd;
  pfd->events = mask;
  return 1;
}

static twopence_io_ops_t twopence_file_io = {
	.close	= twopence_substream_file_close,
	.read	= twopence_substream_file_read,
	.write	= twopence_substream_file_write,
	.set_blocking = twopence_substream_file_set_blocking,
	.poll	= twopence_substream_file_poll,
};

twopence_substream_t *
twopence_substream_new_fd(int fd, bool closeit)
{
  twopence_substream_t *io;

  io = __twopence_substream_new(&twopence_file_io);
  io->fd = fd;
  io->close = closeit;
  return io;
}

twopence_substream_t *
twopence_iostream_stdout(void)
{
  return twopence_substream_new_fd(1, false);
}

twopence_substream_t *
twopence_iostream_stderr(void)
{
  return twopence_substream_new_fd(2, false);
}
