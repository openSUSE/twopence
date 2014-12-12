/*
 * Generic functions implementing the twopence protocol
 * for serial, virtio etc.
 */

#ifndef PROTOCOL_H
#define PROTOCOL_H

/* Once we've changed to a pure function vector interface into the library,
 * these functions should be renamed to __twopence_pipe_*
 */

extern int	twopence_test_and_print_results(struct twopence_target *, const char *, const char *, int *, int *);
extern int	twopence_test_and_drop_results(struct twopence_target *, const char *, const char *, int *, int *);
extern int	twopence_test_and_store_results_together(struct twopence_target *, const char *, const char *,
				char *, int, int *, int *);
extern int	twopence_test_and_store_results_separately(struct twopence_target *, const char *, const char *,
				char *, char *, int, int *, int *);
extern int	twopence_inject_file (struct twopence_target *, const char *, const char *, const char *, int *, bool);
extern int	twopence_extract_file (struct twopence_target *, const char *, const char *, const char *, int *, bool);
extern int	twopence_interrupt_command(struct twopence_target *);
extern int	twopence_exit_remote(struct twopence_target *);
extern void	twopence_end(struct twopence_target *);

#endif /* PROTOCOL_H */
