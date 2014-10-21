#include "util.h"

// Generic plugin
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
  twopence_interrupt_t twopence_interrupt_command;
  twopence_end_t twopence_end;
};

void end_plugin(struct twopence_plugin *self);
struct twopence_plugin *get_plugin(void *handle);

// Virtio plugin
extern struct twopence_plugin virtio_plugin;
int init_virtio_plugin();
void end_virtio_plugin();
void *init_virtio_handle(const char *target);

// Serial plugin
extern struct twopence_plugin serial_plugin;
int init_serial_plugin();
void end_serial_plugin();
void *init_serial_handle(const char *target);

// SSH plugin
extern struct twopence_plugin ssh_plugin;
int init_ssh_plugin();
void end_ssh_plugin();
void *init_ssh_handle(const char *target);
