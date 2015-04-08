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
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "twopence.h"
#include "utils.h"


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

  spec_copy = twopence_strdup(target_spec);
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
 * Set target specific options
 */
int
twopence_target_set_option(struct twopence_target *target, int option, const void *value_p)
{
  if (target->ops->set_option == NULL)
    return TWOPENCE_UNSUPPORTED_FUNCTION_ERROR;

  if (value_p == NULL)
    return TWOPENCE_PARAMETER_ERROR;

  return target->ops->set_option(target, option, value_p);
}

/*
 * General API
 */
int
twopence_run_test(struct twopence_target *target, twopence_command_t *cmd, twopence_status_t *status)
{
  if (target->ops->run_test == NULL)
    return TWOPENCE_UNSUPPORTED_FUNCTION_ERROR;

  /* Populate defaults. Instead of hard-coding them, we could also set
   * default values for a given target. */
  if (cmd->timeout == 0)
    cmd->timeout = 60;
  if (cmd->user == NULL)
    cmd->user = "root";

  return target->ops->run_test(target, cmd, status);
}

int
twopence_wait(struct twopence_target *target, int pid, twopence_status_t *status)
{
  if (target->ops->wait == NULL)
    return TWOPENCE_UNSUPPORTED_FUNCTION_ERROR;

  return target->ops->wait(target, pid, status);
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
   twopence_buf_t *buffer, twopence_status_t *status)
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
   twopence_buf_t *stdout_buffer, twopence_buf_t *stderr_buffer, twopence_status_t *status)
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
  twopence_status_t status;
  twopence_file_xfer_t xfer;
  int rv;

  twopence_file_xfer_init(&xfer);

  /* Open the file */
  rv = twopence_iostream_open_file(local_path, &xfer.local_stream);
  if (rv < 0)
    return rv;

  xfer.user = username;
  xfer.remote.name = remote_path;
  xfer.remote.mode = 0660;
  xfer.print_dots = print_dots;

  rv = twopence_send_file(target, &xfer, &status);

  twopence_file_xfer_destroy(&xfer);
  return rv;
}

int
twopence_send_file(struct twopence_target *target, twopence_file_xfer_t *xfer, twopence_status_t *status)
{
  if (target->ops->inject_file == NULL)
    return TWOPENCE_UNSUPPORTED_FUNCTION_ERROR;

  if (xfer->local_stream == NULL)
    return TWOPENCE_PARAMETER_ERROR;

  if (xfer->user == NULL)
    xfer->user = "root";
  if (xfer->remote.mode == 0)
    xfer->remote.mode = 0644;

  memset(status, 0, sizeof(*status));
  return target->ops->inject_file(target, xfer, status);
}

int
twopence_extract_file
  (struct twopence_target *target, const char *username,
   const char *remote_path, const char *local_path,
   int *remote_rc, bool print_dots)
{
  twopence_status_t status;
  twopence_file_xfer_t xfer;
  int rv;

  twopence_file_xfer_init(&xfer);

  /* Open the file */
  rv = twopence_iostream_create_file(local_path, 0660, &xfer.local_stream);
  if (rv < 0)
    return rv;

  xfer.user = username;
  xfer.remote.name = remote_path;
  xfer.remote.mode = 0660;
  xfer.print_dots = print_dots;

  rv = twopence_recv_file(target, &xfer, &status);

  twopence_file_xfer_destroy(&xfer);
  return rv;
}

int
twopence_recv_file(struct twopence_target *target, twopence_file_xfer_t *xfer, twopence_status_t *status)
{
  if (target->ops->inject_file == NULL)
    return TWOPENCE_UNSUPPORTED_FUNCTION_ERROR;

  if (xfer->local_stream == NULL)
    return TWOPENCE_PARAMETER_ERROR;

  if (xfer->user == NULL)
    xfer->user = "root";
  if (xfer->remote.mode == 0)
    xfer->remote.mode = 0644;

  memset(status, 0, sizeof(*status));
  return target->ops->extract_file(target, xfer, status);
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
    case TWOPENCE_INTERNAL_ERROR:
      return "Internal error";
    case TWOPENCE_TRANSPORT_ERROR:
      return "Error sending or receiving data on socket";
    case TWOPENCE_INCOMPATIBLE_PROTOCOL_ERROR:
      return "Protocol versions not compatible between client and server";
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

static inline twopence_buf_t *
__twopence_command_buffer(twopence_command_t *cmd, twopence_iofd_t dst)
{
  if (0 <= dst && dst < __TWOPENCE_IO_MAX)
    return &cmd->buffer[dst];
  return NULL;
}

twopence_buf_t *
twopence_command_alloc_buffer(twopence_command_t *cmd, twopence_iofd_t dst, size_t size)
{
  twopence_buf_t *bp;

  if ((bp = __twopence_command_buffer(cmd, dst)) == NULL)
    return NULL;

  twopence_buf_destroy(bp);
  if (size)
    twopence_buf_resize(bp, size);
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
twopence_command_ostream_capture(twopence_command_t *cmd, twopence_iofd_t dst, twopence_buf_t *bp)
{
  twopence_iostream_t *stream;

  if ((stream = __twopence_command_ostream(cmd, dst)) != NULL)
    twopence_iostream_add_substream(stream, twopence_substream_new_buffer(bp, false));
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
    twopence_buf_destroy(&cmd->buffer[i]);
    twopence_iostream_destroy(&cmd->iostream[i]);
  }
}

/*
 * File transfer object
 */
void
twopence_file_xfer_init(twopence_file_xfer_t *xfer)
{
  memset(xfer, 0, sizeof(*xfer));
  xfer->remote.mode = 0640;
}

void
twopence_file_xfer_destroy(twopence_file_xfer_t *xfer)
{
  if (xfer->local_stream) {
    twopence_iostream_free(xfer->local_stream);
    xfer->local_stream = NULL;
  }
}
