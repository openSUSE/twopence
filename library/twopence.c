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
    return TWOPENCE_UNKNOWN_PLUGIN;

  *ret = plugins[type];
  if (*ret == NULL)
    return TWOPENCE_UNKNOWN_PLUGIN;

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
    return TWOPENCE_INVALID_TARGET_SPEC;

  rc = __twopence_get_plugin_ops(name, &plugin);
  if (rc < 0)
    return rc;

  /* FIXME: check a version number provided by the plugin data */

  if (plugin->init == NULL)
    return TWOPENCE_INCOMPATIBLE_PLUGIN;

  /* Create the handle */
  target = plugin->init(target_spec);
  if (target == NULL)
    return TWOPENCE_UNKNOWN_PLUGIN;

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
static inline twopence_iostream_t *
__twopence_target_ostream(struct twopence_target *target, twopence_iofd_t dst)
{
  if (0 <= dst && dst < __TWOPENCE_IO_MAX)
    return &target->current.sink[dst];

  return NULL;
}

int
twopence_target_putc(struct twopence_target *target, twopence_iofd_t dst, char c)
{
  twopence_iostream_t *chain;

  if ((chain = __twopence_target_ostream(target, dst)) == NULL)
    return -1;

  twopence_iostream_putc(chain, c);
  return 1;
}

int
twopence_target_write(struct twopence_target *target, twopence_iofd_t dst, const char *data, size_t len)
{
  twopence_iostream_t *chain;

  if ((chain = __twopence_target_ostream(target, dst)) == NULL)
    return -1;

  twopence_iostream_write(chain, data, len);
  return 1;
}

/*
 * General API
 */
int
twopence_run_test(struct twopence_target *target, twopence_command_t *cmd, twopence_status_t *status)
{
  if (target->ops->run_test == NULL)
    return TWOPENCE_NOT_SUPPORTED;

  return target->ops->run_test(target, cmd, status);
}

int
twopence_test_and_print_results(struct twopence_target *target, const char *username, const char *command, twopence_status_t *status)
{
  if (target->ops->run_test) {
    twopence_command_t cmd;

    twopence_command_init(&cmd, command);
    cmd.user = username;

    twopence_command_ostream_redirect(&cmd, TWOPENCE_STDOUT, 1);
    twopence_command_ostream_redirect(&cmd, TWOPENCE_STDERR, 2);

    twopence_source_init_fd(&cmd.source, 0);

    return twopence_run_test(target, &cmd, status);
  }

  return TWOPENCE_NOT_SUPPORTED;
}

int
twopence_test_and_drop_results(struct twopence_target *target, const char *username, const char *command, twopence_status_t *status)
{
  if (target->ops->run_test) {
    twopence_command_t cmd;

    twopence_command_init(&cmd, command);
    cmd.user = username;

    /* Reset both ostreams to nothing */
    twopence_command_ostreams_reset(&cmd);

    twopence_source_init_fd(&cmd.source, 0);

    return twopence_run_test(target, &cmd, status);
  }

  return TWOPENCE_NOT_SUPPORTED;
}

int
twopence_test_and_store_results_together(struct twopence_target *target, const char *username, const char *command,
		twopence_buffer_t *buffer, twopence_status_t *status)
{
  if (target->ops->run_test) {
    twopence_command_t cmd;

    twopence_command_init(&cmd, command);
    cmd.user = username;

    twopence_command_ostreams_reset(&cmd);
    if (buffer) {
      twopence_command_ostream_capture(&cmd, TWOPENCE_STDOUT, buffer);
      twopence_command_ostream_capture(&cmd, TWOPENCE_STDERR, buffer);
    }

    twopence_source_init_fd(&cmd.source, 0);
    return twopence_run_test(target, &cmd, status);
  }

  return TWOPENCE_NOT_SUPPORTED;
}

int
twopence_test_and_store_results_separately(struct twopence_target *target, const char *username, const char *command,
		twopence_buffer_t *stdout_buffer, twopence_buffer_t *stderr_buffer, twopence_status_t *status)
{
  if (target->ops->run_test) {
    twopence_command_t cmd;

    twopence_command_init(&cmd, command);
    cmd.user = username;

    twopence_command_ostreams_reset(&cmd);
    if (stdout_buffer)
      twopence_command_ostream_capture(&cmd, TWOPENCE_STDOUT, stdout_buffer);
    if (stderr_buffer)
      twopence_command_ostream_capture(&cmd, TWOPENCE_STDERR, stderr_buffer);

    twopence_source_init_fd(&cmd.source, 0);

    return twopence_run_test(target, &cmd, status);
  }

  return TWOPENCE_NOT_SUPPORTED;
}

int
twopence_inject_file(struct twopence_target *target, const char *username,
		const char *local_path, const char *remote_path,
		int *remote_rc, bool print_dots)
{
  if (target->ops->inject_file == NULL)
    return TWOPENCE_NOT_SUPPORTED;

  /* Reset output, and connect with stdout if we want to see the dots get printed */
  target->current.sink = NULL;
  if (print_dots)
    __twopence_setup_stdout(target);

  twopence_source_init_none(&target->current.source);

  return target->ops->inject_file(target, username, local_path, remote_path, remote_rc, print_dots);
}

int
twopence_extract_file(struct twopence_target *target, const char *username,
		const char *remote_path, const char *local_path,
		int *remote_rc, bool print_dots)
{
  if (target->ops->extract_file == NULL)
    return TWOPENCE_NOT_SUPPORTED;

  /* Reset output, and connect with stdout if we want to see the dots get printed */
  target->current.sink = NULL;
  if (print_dots)
    __twopence_setup_stdout(target);

  twopence_source_init_none(&target->current.source);

  return target->ops->extract_file(target, username, remote_path, local_path, remote_rc, print_dots);
}

int
twopence_exit_remote(struct twopence_target *target)
{
  if (target->ops->exit_remote == NULL)
    return TWOPENCE_NOT_SUPPORTED;

  return target->ops->exit_remote(target);
}

int
twopence_interrupt_command(struct twopence_target *target)
{
  if (target->ops->interrupt_command == NULL)
    return TWOPENCE_NOT_SUPPORTED;

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
    case TWOPENCE_INVALID_TARGET_SPEC:
      return "Invalid target spec";
    case TWOPENCE_UNKNOWN_PLUGIN:
      return "Unknown plugin";
    case TWOPENCE_INCOMPATIBLE_PLUGIN:
      return "Incompatible plugin";
    case TWOPENCE_NOT_SUPPORTED:
      return "Operation not supported";
    case TWOPENCE_PROTOCOL_ERROR:
      return "Protocol error";
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

  twopence_source_init_none(&cmd->source);

  /* By default, all output from the remote command is sent to our own
   * stdout and stderr */
  twopence_command_ostream_redirect(cmd, TWOPENCE_STDOUT, 1);
  twopence_command_ostream_redirect(cmd, TWOPENCE_STDERR, 2);

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
    return &cmd->sink[dst];
  return NULL;
}

void
twopence_command_ostreams_reset(twopence_command_t *cmd)
{
  unsigned int i;

  for (i = 0; i < __TWOPENCE_IO_MAX; ++i)
    twopence_iostream_destroy(&cmd->sink[i]);
}

void
twopence_command_ostream_reset(twopence_command_t *cmd, twopence_iofd_t dst)
{
  twopence_iostream_t *chain;

  if ((chain = __twopence_command_ostream(cmd, dst)) != NULL)
    twopence_iostream_destroy(chain);
}

void
twopence_command_ostream_capture(twopence_command_t *cmd, twopence_iofd_t dst, twopence_buffer_t *bp)
{
  twopence_iostream_t *chain;

  if ((chain = __twopence_command_ostream(cmd, dst)) != NULL)
    twopence_iostream_add_substream(chain, twopence_substream_new_buffer(bp));
}

void
twopence_command_ostream_redirect(twopence_command_t *cmd, twopence_iofd_t dst, int fd)
{
  twopence_iostream_t *chain;

  if ((chain = __twopence_command_ostream(cmd, dst)) != NULL)
    twopence_iostream_add_substream(chain, twopence_substream_new_fd(fd));
}

void
twopence_command_destroy(twopence_command_t *cmd)
{
  unsigned int i;

  for (i = 0; i < __TWOPENCE_IO_MAX; ++i) {
    twopence_buffer_free(&cmd->buffer[i]);
    twopence_iostream_destroy(&cmd->sink[i]);
  }
  twopence_source_destroy(&cmd->source);
}

/*
 * Switch stdin blocking mode
 */
int
twopence_tune_stdin(bool blocking)
{
  int flags;

  flags = fcntl(0, F_GETFL, 0);        // Get old flags
  if (flags == -1)
    return -1;

  flags &= ~O_NONBLOCK;
  if (blocking)
    flags |= O_NONBLOCK;

  return fcntl(0, F_SETFL, flags);
}

/*
 * Input handling
 */
void
twopence_source_init_none(twopence_source_t *src)
{
  src->fd = -1;
}

void
twopence_source_init_fd(twopence_source_t *src, int fd)
{
  src->fd = fd;
}

void
twopence_source_destroy(twopence_source_t *src)
{
  if (src->fd >= 0) {
    close(src->fd);
    src->fd = -1;
  }
}

int
twopence_source_set_blocking(twopence_source_t *src, bool blocking)
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
  static twopence_iostream_t dots_sink[__TWOPENCE_IO_MAX];

  if (dots_sink[TWOPENCE_STDOUT].count == 0)
    twopence_iostream_add_substream(&dots_sink[TWOPENCE_STDOUT], twopence_substream_new_fd(1));

  target->current.sink = dots_sink;
}


void
twopence_iostream_add_substream(twopence_iostream_t *chain, twopence_substream_t *sink)
{
  if (chain->count >= 4) {
    free(sink);
    return;
  }

  chain->sink[chain->count++] = sink;
}

void
twopence_iostream_destroy(twopence_iostream_t *chain)
{
  unsigned int i;

  for (i = 0; i < chain->count; ++i)
    free(chain->sink[i]);
  memset(chain, 0, sizeof(chain));
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
 * Write to a sink object
 */
int
twopence_iostream_putc(twopence_iostream_t *chain, char c)
{
  unsigned int i;

  if (chain->count == 0)
    return 0;

  for (i = 0; i < chain->count; ++i) {
    twopence_substream_t *sink = chain->sink[i];

    if (sink->ops == NULL || sink->ops->write == NULL)
      return -1;
    sink->ops->write(sink, &c, 1);
  }

  return 1;
}

int
twopence_iostream_write(twopence_iostream_t *chain, const char *data, size_t len)
{
  unsigned int i;

  if (chain->count == 0)
    return 0;

  for (i = 0; i < chain->count; ++i) {
    twopence_substream_t *sink = chain->sink[i];

    if (sink->ops == NULL || sink->ops->write == NULL)
      return -1;
    sink->ops->write(sink, data, len);
  }

  return len;
}

/*
 * Create a new sink object
 */
twopence_substream_t *
__twopence_substream_new(const twopence_io_ops_t *ops)
{
  twopence_substream_t *sink;

  sink = calloc(1, sizeof(*sink));
  sink->ops = ops;

  return sink;
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

static twopence_io_ops_t twopence_file_io = {
	.read	= twopence_substream_file_read,
	.write	= twopence_substream_file_write,
};

twopence_substream_t *
twopence_substream_new_fd(int fd)
{
  twopence_substream_t *io;

  io = __twopence_substream_new(&twopence_file_io);
  io->fd = fd;
  return io;
}

twopence_substream_t *
twopence_iostream_stdout(void)
{
  return twopence_substream_new_fd(1);
}

twopence_substream_t *
twopence_iostream_stderr(void)
{
  return twopence_substream_new_fd(2);
}
