#include <ruby.h>

VALUE method_init(VALUE self, VALUE ruby_target);
VALUE method_test_and_print_results(VALUE self, VALUE ruby_user, VALUE ruby_command);
VALUE method_test_and_drop_results(VALUE self, VALUE ruby_user, VALUE ruby_command);
VALUE method_test_and_store_results_together(VALUE self, VALUE ruby_user, VALUE ruby_command);
VALUE method_test_and_store_results_separately(VALUE self, VALUE ruby_user, VALUE ruby_command);
VALUE method_inject_file(VALUE self, VALUE ruby_user, VALUE ruby_local_file, VALUE ruby_remote_file, VALUE ruby_dots);
VALUE method_extract_file(VALUE self, VALUE ruby_user, VALUE ruby_remote_file, VALUE ruby_local_file, VALUE ruby_dots);
VALUE method_exit(VALUE self);
