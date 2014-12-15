/*
 * Generic functions implementing the twopence protocol
 * for serial, virtio etc.
 */

#ifndef PROTOCOL_H
#define PROTOCOL_H

/* Base class for all targets using the twopence pipe protocol */
struct twopence_pipe_target {
  struct twopence_target base;

  enum { no_output, to_screen, common_buffer, separate_buffers } output_mode;
  char *buffer_out, *end_out;
  char *buffer_err, *end_err;
};


/* Once we've changed to a pure function vector interface into the library,
 * these functions should be renamed to __twopence_pipe_*
 */

extern void	twopence_pipe_target_init(struct twopence_pipe_target *, int plugin_type, const struct twopence_plugin *);

extern int	twopence_pipe_test_and_print_results(struct twopence_target *, const char *, const char *, int *, int *);
extern int	twopence_pipe_test_and_drop_results(struct twopence_target *, const char *, const char *, int *, int *);
extern int	twopence_pipe_test_and_store_results_together(struct twopence_target *, const char *, const char *,
				char *, int, int *, int *);
extern int	twopence_pipe_test_and_store_results_separately(struct twopence_target *, const char *, const char *,
				char *, char *, int, int *, int *);
extern int	twopence_pipe_inject_file (struct twopence_target *, const char *, const char *, const char *, int *, bool);
extern int	twopence_pipe_extract_file (struct twopence_target *, const char *, const char *, const char *, int *, bool);
extern int	twopence_pipe_interrupt_command(struct twopence_target *);
extern int	twopence_pipe_exit_remote(struct twopence_target *);
extern void	twopence_pipe_end(struct twopence_target *);

#endif /* PROTOCOL_H */
