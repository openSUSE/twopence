/*
Based on the utility routines for Twopence.

Copyright (C) 2014 SUSE

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
#include <dlfcn.h>
#include <fcntl.h>

#include "twopence.h"

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
  char *plugin, *s;
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

/*
 * Open the shared library for this plugin type
 */
static void *
twopence_load_library(const char *plugin)
{
  char libname[256];
  void *dl_handle;

  snprintf(libname, sizeof(libname), "libtwopence_%s.so.%u", plugin, TWOPENCE_API_MAJOR_VERSION);
  dl_handle = dlopen(libname, RTLD_LAZY); 
  if (dl_handle == NULL)
    fprintf(stderr, "Cannot open shared library \"%s\"\n", libname);
  return dl_handle;
}

/*
 * Get a symbol from the DLL
 */
static void *
twopence_get_symbol(void *dl_handle, const char *sym_name)
{
  return dlsym(dl_handle, sym_name);
}

static int
__twopence_get_plugin_ops(const char *name, const struct twopence_plugin **ret)
{
  static void *plugin_dl_handles[__TWOPENCE_PLUGIN_MAX];
  const struct twopence_plugin *plugin;
  int type;
  void *dl_handle;

  type = twopence_plugin_type(name);
  if (type == TWOPENCE_PLUGIN_UNKNOWN 
   || type >= __TWOPENCE_PLUGIN_MAX)
    return TWOPENCE_UNKNOWN_PLUGIN;

  dl_handle = plugin_dl_handles[type];
  if (dl_handle == NULL) {
    dl_handle = twopence_load_library(name);
    if (dl_handle == NULL)
      return TWOPENCE_UNKNOWN_PLUGIN;

    plugin_dl_handles[type] = dl_handle;
  }

  plugin = (const struct twopence_plugin *) twopence_get_symbol(dl_handle, "twopence_plugin");
  if (plugin == NULL) {
    char symbol[128];

    snprintf(symbol, sizeof(symbol), "twopence_%s_ops", name);
    plugin = (const struct twopence_plugin *) twopence_get_symbol(dl_handle, symbol);
  }
 
  if (plugin == NULL) {
    fprintf(stderr, "plugin \"%s\" does not provide a function vector\n", name);
    return TWOPENCE_INCOMPATIBLE_PLUGIN;
  }

  *ret = plugin;
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
  }
  return "Unknow error";
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
