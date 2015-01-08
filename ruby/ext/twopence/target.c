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

#include "twopence.h"

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
  struct twopence_target *target;
  VALUE ruby_target_class;
  const char *target_spec;
  int rc;

  Check_Type(ruby_target, T_STRING);

  target_spec = StringValueCStr(ruby_target);
  rc = twopence_target_new(target_spec, &target);
  if (rc < 0) {
    fprintf(stderr, "Error while initializing library: %s\n", twopence_strerror(rc));
    return Qnil;
  }

  // Return a new Ruby target wrapping the C handle
  ruby_target_class = rb_const_get(self, rb_intern("Target"));
  return Data_Wrap_Struct(ruby_target_class, NULL, deallocate_target, target);
}

// Destructor
void deallocate_target(void *handle)
{
  struct twopence_target *target = (struct twopence_target *) handle;

  twopence_target_free(target);
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
  struct twopence_target *target;
  int rc, major, minor;

  Check_Type(ruby_user, T_STRING);
  Check_Type(ruby_command, T_STRING);
  Data_Get_Struct(self, struct twopence_target, target);

  rc = twopence_test_and_print_results
    (target, StringValueCStr(ruby_user), StringValueCStr(ruby_command),
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
  struct twopence_target *target;
  int rc, major, minor;

  Check_Type(ruby_user, T_STRING);
  Check_Type(ruby_command, T_STRING);
  Data_Get_Struct(self, struct twopence_target, target);

  rc = twopence_test_and_drop_results
    (target, StringValueCStr(ruby_user), StringValueCStr(ruby_command),
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
  struct twopence_target *target;
  int rc, major, minor;

  Check_Type(ruby_user, T_STRING);
  Check_Type(ruby_command, T_STRING);
  Data_Get_Struct(self, struct twopence_target, target);

  rc = twopence_test_and_store_results_together
    (target, StringValueCStr(ruby_user), StringValueCStr(ruby_command),
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
  struct twopence_target *target;
  char *buffer_out = output_buffer,
       *buffer_err = output_buffer + 32768;
  int rc, major, minor;

  Check_Type(ruby_user, T_STRING);
  Check_Type(ruby_command, T_STRING);
  Data_Get_Struct(self, struct twopence_target, target);

  rc = twopence_test_and_store_results_separately
    (target, StringValueCStr(ruby_user), StringValueCStr(ruby_command),
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
  struct twopence_target *target;
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
  Data_Get_Struct(self, struct twopence_target, target);

  rc = twopence_inject_file
    (target, StringValueCStr(ruby_user), StringValueCStr(ruby_local_file), StringValueCStr(ruby_remote_file),
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
  struct twopence_target *target;
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
  Data_Get_Struct(self, struct twopence_target, target);

  rc = twopence_extract_file
    (target, StringValueCStr(ruby_user), StringValueCStr(ruby_remote_file), StringValueCStr(ruby_local_file),
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
  struct twopence_target *target;
  int rc;

  Data_Get_Struct(self, struct twopence_target, target);

  rc = twopence_interrupt_command(target);

  return INT2NUM(rc);
}

// Tell the test server to exit
//
// Example:
//   rc = target.exit_remote()
//     rc: the return code of the testing platform
VALUE method_exit(VALUE self)
{
  struct twopence_target *target;
  int rc;

  Data_Get_Struct(self, struct twopence_target, target);

  rc = twopence_exit_remote(target);

  return INT2NUM(rc);
}
