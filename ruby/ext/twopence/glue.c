/*
Ruby bindings for Twopence test executor.

Twopence enables to communicate with some testing environment:
libvirt virtual machine, remote host via SSH, or remote host via serial lines.


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

#include "target.h"

// The ruby module
VALUE Twopence = Qnil;

// ******************* Initialization of C extension *************************

// Initialize the ruby native implementation
void Init_twopence()
{
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
  rb_define_method(ruby_target_class, "interrupt_command", method_interrupt_command, 0);
  rb_define_method(ruby_target_class, "exit", method_exit, 0);
}
