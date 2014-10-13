/*
Ruby bindings for Twopence test executor. They enable to communicate
with some testing environment: libvirt virtual machine, remote host
via SSH, or remote host via serial lines.


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

#include <stdbool.h>
#include <ruby.h>
#include <dlfcn.h>

#include "util.h"

// The ruby module
VALUE Twopence = Qnil;

// The shared buffer
char output_buffer[65536];

void deallocate_target(void *);

// ******************* Generic plugin ****************************************

// The two plugins as instances of a generic plugin
// (yes, this is object oriented programming with polymorphism in C - how strange)
struct twopence_plugin
{
  int refcount;
  void *dl_handle;

  void *twopence_init;                 // either twopence_init_virtio_t, twopence_init_ssh_t, or twopence_init_serial_t
  twopence_test_t1 twopence_test_and_print_results;
  twopence_test_t1 twopence_test_and_drop_results;
  twopence_test_t2 twopence_test_and_store_results_together;
  twopence_test_t3 twopence_test_and_store_results_separately;
  twopence_inject_t twopence_inject_file;
  twopence_extract_t twopence_extract_file;
  twopence_exit_t twopence_exit_remote;
  twopence_end_t twopence_end;
} virtio_plugin, ssh_plugin, serial_plugin;

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

// ******************* Methods of module Twopence ****************************

// Create a test target
//
// Example for the virtio plugin:
//   target = Twopence::init("virtio:/tmp/sut.sock")
//     target: an object that describes your system under test,
//             and that you will need for subsequent calls
//
// Example for the ssh plugin:
//   target = Twopence::init("ssh:host.example.com")
//
// Example for the serial plugin:
//   target = Twopence::init("serial:/dev/ttyS0")
VALUE method_init(VALUE self, VALUE ruby_target)
{
  void *handle;
  VALUE ruby_target_class;

  Check_Type(ruby_target, T_STRING);

  // Load library and create a target handle
  switch (target_plugin
            (StringValueCStr(ruby_target)))
  {
    case 0:                            // virtio
      if (init_virtio_plugin() < 0)
        return Qnil;
      handle = init_virtio_handle
        (StringValueCStr(ruby_target));
      if (handle == NULL)
      {
        end_virtio_plugin();
        return Qnil;
      }
      break;
    case 1:                            // ssh
      if (init_ssh_plugin() < 0)
        return Qnil;
      handle = init_ssh_handle
        (StringValueCStr(ruby_target));
      if (handle == NULL)
      {
        end_ssh_plugin();
        return Qnil;
      }
      break;
    case 2:                            // serial
      if (init_serial_plugin() < 0)
        return Qnil;
      handle = init_serial_handle
        (StringValueCStr(ruby_target));
      if (handle == NULL)
      {
        end_serial_plugin();
        return Qnil;
      }
      break;
    default:                           // unknown
      return Qnil;
  }

  // Return a new Ruby target wrapping the C handle
  ruby_target_class = rb_const_get(self, rb_intern("Target"));
  return Data_Wrap_Struct(ruby_target_class, NULL, deallocate_target, handle);
}

// ******************* Methods of class Twopence::Target *********************

// Run a test command, and print output
//
// Example:
//   rc, major, minor = target.test_and_print_results("johndoe", "ls -l")
//     rc: the return code of the testing platform
//     major: the return code of the system under test
//     minor: the return code of the command
VALUE method_test_and_print_results(VALUE self, VALUE ruby_user, VALUE ruby_command)
{
  void *handle;
  const struct twopence_plugin *plugin;
  int rc, major, minor;

  Check_Type(ruby_user, T_STRING);
  Check_Type(ruby_command, T_STRING);
  Data_Get_Struct(self, void, handle);

  plugin = get_plugin(handle);
  rc = (*plugin->twopence_test_and_print_results)
    (handle, StringValueCStr(ruby_user), StringValueCStr(ruby_command),
     &major, &minor);

  return rb_ary_new3(3,
                     INT2NUM(rc), INT2NUM(major), INT2NUM(minor));
}

// Run a test command, and drop output
//
// Example:
//   rc, major, minor = target.test_and_drop_results("johndoe", "ping -c1 8.8.8.8")
//     rc: the return code of the testing platform
//     major: the return code of the system under test
//     minor: the return code of the command
VALUE method_test_and_drop_results(VALUE self, VALUE ruby_user, VALUE ruby_command)
{
  void *handle;
  const struct twopence_plugin *plugin;
  int rc, major, minor;

  Check_Type(ruby_user, T_STRING);
  Check_Type(ruby_command, T_STRING);
  Data_Get_Struct(self, void, handle);

  plugin = get_plugin(handle);
  rc = (*plugin->twopence_test_and_drop_results)
    (handle, StringValueCStr(ruby_user), StringValueCStr(ruby_command),
     &major, &minor);

  return rb_ary_new3(3,
                     INT2NUM(rc), INT2NUM(major), INT2NUM(minor));
}

// Run a test command, and store the result in a common string
//
// Example:
//   out, rc, major, minor = target.test_and_store_results_together("johndoe", "ifconfig -a")
//     out: the standard output of the command
//     rc: the return code of the testing platform
//     major: the return code of the system under test
//     minor: the return code of the command
VALUE method_test_and_store_results_together(VALUE self, VALUE ruby_user, VALUE ruby_command)
{
  void *handle;
  const struct twopence_plugin *plugin;
  int rc, major, minor;

  Check_Type(ruby_user, T_STRING);
  Check_Type(ruby_command, T_STRING);
  Data_Get_Struct(self, void, handle);

  plugin = get_plugin(handle);
  rc = (*plugin->twopence_test_and_store_results_together)
    (handle, StringValueCStr(ruby_user), StringValueCStr(ruby_command),
     output_buffer, 65536,
     &major, &minor);

  return rb_ary_new3(4,
                     rb_str_new(output_buffer, strlen(output_buffer)),
                     INT2NUM(rc), INT2NUM(major), INT2NUM(minor));
}

// Run a test command, and store the result in two separate strings
//
// Example:
//   out, err, rc, major, minor = target.test_and_store_results_separately("nobody", "find /etc -type l")
//     out: the standard output of the command
//     err: the standard error of the command
//     rc: the return code of the testing platform
//     major: the return code of the system under test
//     minor: the return code of the command
VALUE method_test_and_store_results_separately(VALUE self, VALUE ruby_user, VALUE ruby_command)
{
  void *handle;
  const struct twopence_plugin *plugin;
  char *buffer_out = output_buffer,
       *buffer_err = output_buffer + 32768;
  int rc, major, minor;

  Check_Type(ruby_user, T_STRING);
  Check_Type(ruby_command, T_STRING);
  Data_Get_Struct(self, void, handle);

  plugin = get_plugin(handle);
  rc = (*plugin->twopence_test_and_store_results_separately)
    (handle, StringValueCStr(ruby_user), StringValueCStr(ruby_command),
     buffer_out, buffer_err, 32768,
     &major, &minor);

  return rb_ary_new3(5,
                     rb_str_new(buffer_out, strlen(buffer_out)),
                     rb_str_new(buffer_err, strlen(buffer_err)),
                     INT2NUM(rc), INT2NUM(major), INT2NUM(minor));
}

// Inject a file into the system under test
//
// Example:
//   rc, remote = target.inject_file("johndoe", "/etc/services", "remote.txt", true)
//     rc: the return code of the testing platform
//     remote: the return code of the system under test
VALUE method_inject_file(VALUE self, VALUE ruby_user, VALUE ruby_local_file, VALUE ruby_remote_file, VALUE ruby_dots)
{
  bool dots;
  void *handle;
  const struct twopence_plugin *plugin;
  int rc, remote_rc;

  Check_Type(ruby_user, T_STRING);
  Check_Type(ruby_local_file, T_STRING);
  Check_Type(ruby_remote_file, T_STRING);
  switch (TYPE(ruby_dots))
  {
    case T_TRUE: dots = true; break;
    case T_FALSE: dots = false; break;
    default: rb_raise(rb_eTypeError, "expected a boolean value");
  }
  Data_Get_Struct(self, void, handle);

  plugin = get_plugin(handle);
  rc = (*plugin->twopence_inject_file)
    (handle, StringValueCStr(ruby_user), StringValueCStr(ruby_local_file), StringValueCStr(ruby_remote_file),
     &remote_rc, dots);

  return rb_ary_new3(2,
                     INT2NUM(rc), INT2NUM(remote_rc));
}

// Extract a file from the system under test
//
// Example:
//   rc, remote = target.extract_file("root", "/etc/services", "remote.txt", true)
//     rc: the return code of the testing platform
//     remote: the return code of the system under test
VALUE method_extract_file(VALUE self, VALUE ruby_user, VALUE ruby_remote_file, VALUE ruby_local_file, VALUE ruby_dots)
{
  bool dots;
  void *handle;
  const struct twopence_plugin *plugin;
  int rc, remote_rc;

  Check_Type(ruby_user, T_STRING);
  Check_Type(ruby_remote_file, T_STRING);
  Check_Type(ruby_local_file, T_STRING);
  switch (TYPE(ruby_dots))
  {
    case T_TRUE: dots = true; break;
    case T_FALSE: dots = false; break;
    default: rb_raise(rb_eTypeError, "expected a boolean value");
  }
  Data_Get_Struct(self, void, handle);

  plugin = get_plugin(handle);
  rc = (*plugin->twopence_extract_file)
    (handle, StringValueCStr(ruby_user), StringValueCStr(ruby_remote_file), StringValueCStr(ruby_local_file),
     &remote_rc, dots);

  return rb_ary_new3(2,
                     INT2NUM(rc), INT2NUM(remote_rc));
}

// Tell the test server to exit
//
// Example:
//   rc = target.exit_remote()
//     rc: the return code of the testing platform
VALUE method_exit(VALUE self)
{
  void *handle;
  const struct twopence_plugin *plugin;
  int rc;

  Data_Get_Struct(self, void, handle);

  plugin = get_plugin(handle);
  rc = (*plugin->twopence_exit_remote)(handle);

  return INT2NUM(rc);
}

// Destructor
void deallocate_target(void *handle)
{
  struct twopence_plugin *plugin;

  plugin = get_plugin(handle);
  (*plugin->twopence_end)(handle);     // Call the end() function for this target

  end_plugin(plugin);                  // One less reference for this plugin, try to release the library
}

// ******************* Initialization of C extension *************************

// Initialize the ruby native implementation
void Init_twopence()
{
  // C initializations
  virtio_plugin.refcount = 0;
  virtio_plugin.dl_handle = NULL;
  ssh_plugin.refcount = 0;
  ssh_plugin.dl_handle = NULL;

  // Ruby initializations
  VALUE ruby_target_class;

  Twopence = rb_define_module("Twopence");
  rb_define_singleton_method(Twopence, "init", method_init, 1);

  ruby_target_class = rb_define_class_under(Twopence, "Target", rb_cObject);
  rb_define_method(ruby_target_class, "test_and_print_results", method_test_and_print_results, 2);
  rb_define_method(ruby_target_class, "test_and_drop_results", method_test_and_drop_results, 2);
  rb_define_method(ruby_target_class, "test_and_store_results_separately", method_test_and_store_results_separately, 2);
  rb_define_method(ruby_target_class, "test_and_store_results_together", method_test_and_store_results_together, 2);
  rb_define_method(ruby_target_class, "inject_file", method_inject_file, 4);
  rb_define_method(ruby_target_class, "extract_file", method_extract_file, 4);
  rb_define_method(ruby_target_class, "exit", method_exit, 0);
}
