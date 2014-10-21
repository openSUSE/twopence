/*
Plugins for Twopence test executor ruby bindings.


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
#include <dlfcn.h>

#include "plugins.h"

// ******************* Generic plugin ****************************************

// The three plugins as instances of a generic plugin
// (yes, this is object oriented programming with polymorphism in C - how strange)
struct twopence_plugin
  virtio_plugin, ssh_plugin, serial_plugin;

// Initialize the plugin
//
// Returns 0 if everything went fine, -1 otherwise
int init_plugin(struct twopence_plugin *self, const char *filename)
{
  void *dl_handle;

  // No need to do so if it has already been done
  if (self->refcount > 0)
  {
    self->refcount++;
    return 0;
  }

  // Open the C library
  dl_handle = open_library(filename);
  if (dl_handle == NULL) return -1;

  // Get the symbols
  self->twopence_init =
    get_function(dl_handle, "twopence_init");
  self->twopence_test_and_print_results =
    get_function(dl_handle, "twopence_test_and_print_results");
  self->twopence_test_and_drop_results =
    get_function(dl_handle, "twopence_test_and_drop_results");
  self->twopence_test_and_store_results_together =
    get_function(dl_handle, "twopence_test_and_store_results_together");
  self->twopence_test_and_store_results_separately =
    get_function(dl_handle, "twopence_test_and_store_results_separately");
  self->twopence_inject_file =
    get_function(dl_handle, "twopence_inject_file");
  self->twopence_extract_file =
    get_function(dl_handle, "twopence_extract_file");
  self->twopence_exit_remote =
    get_function(dl_handle, "twopence_exit_remote");
  self->twopence_interrupt_command =
    get_function(dl_handle, "twopence_interrupt_command");
  self->twopence_end =
    get_function(dl_handle, "twopence_end");

  // Check symbols
  if (self->twopence_init == NULL ||
      self->twopence_test_and_print_results == NULL ||
      self->twopence_test_and_drop_results == NULL ||
      self->twopence_test_and_store_results_separately == NULL ||
      self->twopence_test_and_store_results_together == NULL ||
      self->twopence_inject_file == NULL ||
      self->twopence_extract_file == NULL ||
      self->twopence_exit_remote == NULL ||
      self->twopence_interrupt_command == NULL ||
      self->twopence_end == NULL)
  {
    dlclose(dl_handle);
    return -1;
  }

  // One more reference to the plugin
  self->dl_handle = dl_handle;
  self->refcount++;
  return 0;
}

// End the plugin
void end_plugin(struct twopence_plugin *self)
{
  // Protect against unpaired init/ends
  if (self->refcount <= 0)
  {
    fprintf(stderr, "Internal error: unpaired init/end\n");
    return;
  }

  // One less reference
  self->refcount--;

  // Close the shared library, possibly unloading it from memory
  if (self->refcount == 0)
  {
    dlclose(self->dl_handle);
    self->dl_handle = NULL;
  }
}

// Given the handle to a target, get the plugin that manages that target
struct twopence_plugin *get_plugin(void *handle)
{
  switch (*(int *) handle)             // The plugin type is stored at the beginning of the handle
  {                                    // (yes, knowing that detail means the handle is not as opaque as it should be)
    case 0:
      return &virtio_plugin;
    case 1:
      return &ssh_plugin;
    case 2:
      return &serial_plugin;
  }
  return NULL;
}

// ******************* Virtio plugin *****************************************

// Initialize the virtio plugin
//
// Returns 0 if everything went fine, -1 otherwise
int init_virtio_plugin()
{
  return init_plugin(&virtio_plugin, "libtwopence_virtio.so.0");
}

// End the virtio plugin
void end_virtio_plugin()
{
  end_plugin(&virtio_plugin);
}

// Create a C handle to the target
void *init_virtio_handle(const char *target)
{
  char *socketname;
  void *handle;

  socketname = target_virtio_serial_filename(target);
  if (socketname == NULL)
  {
    return NULL;
  }

  handle = (*(twopence_init_virtio_t) virtio_plugin.twopence_init)
    (socketname);

  free(socketname);
  return handle;
}

// ******************* SSH plugin ********************************************

// Initialize the ssh plugin
//
// Returns 0 if everything went fine, -1 otherwise
int init_ssh_plugin()
{
  return init_plugin(&ssh_plugin, "libtwopence_ssh.so.0");
}

// End the ssh plugin
void end_ssh_plugin()
{
  end_plugin(&ssh_plugin);
}

// Create a C handle to the target
void *init_ssh_handle(const char *target)
{
  char *hostname;
  int port;
  void *handle;

  hostname = target_ssh_hostname(target);
  if (hostname == NULL)
  {
    return NULL;
  }

  port = target_ssh_port(target);
  if (port < 0 || port > 65535)
  {
    free(hostname);
    return NULL;
  }

  handle = (*(twopence_init_ssh_t) ssh_plugin.twopence_init)
    (hostname, port);

  free(hostname);
  return handle;
}

// ******************* Serial plugin *****************************************

// Initialize the serial plugin
//
// Returns 0 if everything went fine, -1 otherwise
int init_serial_plugin()
{
  return init_plugin(&serial_plugin, "libtwopence_serial.so.0");
}

// End the serial plugin
void end_serial_plugin()
{
  end_plugin(&serial_plugin);
}

// Create a C handle to the target
void *init_serial_handle(const char *target)
{
  char *devicename;
  void *handle;

  devicename = target_virtio_serial_filename(target);
  if (devicename == NULL)
  {
    return NULL;
  }

  handle = (*(twopence_init_serial_t) serial_plugin.twopence_init)
    (devicename);

  free(devicename);
  return handle;
}
