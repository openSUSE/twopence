/*
Methods to call Twopence library - declaration.


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

#include <ruby.h>

VALUE method_init(VALUE self, VALUE ruby_target);
VALUE method_test_and_print_results(VALUE self, VALUE ruby_args);            // command, user = "root", timeout = 60
VALUE method_test_and_drop_results(VALUE self, VALUE ruby_args);             // command, user = "root", timeout = 60
VALUE method_test_and_store_results_together(VALUE self, VALUE ruby_args);   // command, user = "root", timeout = 60
VALUE method_test_and_store_results_separately(VALUE self, VALUE ruby_args); // command, user = "root", timeout = 60
VALUE method_inject_file(VALUE self, VALUE ruby_args);                       // local_file, remote_file, user = "root", dots = true
VALUE method_extract_file(VALUE self, VALUE ruby_args);                      // remote_file, local_file, user = "root", dots = true
VALUE method_interrupt_command(VALUE self);
VALUE method_exit(VALUE self);
