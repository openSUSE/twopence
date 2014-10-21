/*
Methods to call Twopence library - implementation.


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

#include <ruby.h>

#include "plugins.h"

// The shared buffer
char output_buffer[65536];

void deallocate_target(void *);

// ******************* Methods of module Twopence ****************************

// Create a test target
//
// Example for the virtio plugin:
//   target = Twopence::init("virtio:/tmp/sut.sock")
//
// Example for the ssh plugin:
//   target = Twopence::init("ssh:host.example.com")
//
// Example for the serial plugin:
//   target = Twopence::init("serial:/dev/ttyS0")
//
//     target: an object that describes your system under test,
//             and that you will need for subsequent calls
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

// Destructor
void deallocate_target(void *handle)
{
  struct twopence_plugin *plugin;

  plugin = get_plugin(handle);
  (*plugin->twopence_end)(handle);     // Call the end() function for this target

  end_plugin(plugin);                  // One less reference for this plugin, try to release the library
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

// Interrupt command currently executed
//
// Example:
//   rc = target.exit_remote()
//     rc: the return code of the testing platform
VALUE method_interrupt_command(VALUE self)
{
  void *handle;
  const struct twopence_plugin *plugin;
  int rc;

  Data_Get_Struct(self, void, handle);

  plugin = get_plugin(handle);
  rc = (*plugin->twopence_interrupt_command)(handle);

  return INT2NUM(rc);
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
