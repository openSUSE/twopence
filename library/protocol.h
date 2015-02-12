/*
 * Generic functions implementing the twopence protocol
 * for serial, virtio etc.
 */

#ifndef PROTOCOL_H
#define PROTOCOL_H

/* Base class for all targets using the twopence pipe protocol */
struct twopence_pipe_target {
  struct twopence_target base;

  unsigned long link_timeout;
  const struct twopence_pipe_ops *link_ops;

  int link_fd;
};


struct twopence_pipe_ops {
  int		(*open)(struct twopence_pipe_target *);
  int		(*recv)(struct twopence_pipe_target *, int, char *buffer, size_t count);
  int		(*send)(struct twopence_pipe_target *, int, const char *buffer, size_t count);
};

extern void	twopence_pipe_target_init(struct twopence_pipe_target *, int plugin_type, const struct twopence_plugin *,
			const struct twopence_pipe_ops *);

extern int	twopence_pipe_run_test(struct twopence_target *, twopence_command_t *, twopence_status_t *);
extern int	twopence_pipe_inject_file (struct twopence_target *, const char *, twopence_iostream_t *, const char *, int *, bool);
extern int	twopence_pipe_extract_file (struct twopence_target *, const char *, const char *, twopence_iostream_t *, int *, bool);
extern int	twopence_pipe_interrupt_command(struct twopence_target *);
extern int	twopence_pipe_exit_remote(struct twopence_target *);
extern void	twopence_pipe_end(struct twopence_target *);

#endif /* PROTOCOL_H */
