/*
 * Generic functions implementing the twopence protocol
 * for serial, virtio etc.
 *
 * Copyright (C) 2014-2015 SUSE
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef PIPE_H
#define PIPE_H

#include "protocol.h"

/* Base class for all targets using the twopence pipe protocol */
struct twopence_pipe_target {
  struct twopence_target base;

  unsigned long link_timeout;
  const struct twopence_pipe_ops *link_ops;

  int link_fd;

  twopence_protocol_state_t ps;

  /* "foreground" transaction. This is the transaction that gets
   * cancelled when twopence_interrupt() is called. */
  struct twopence_pipe_transaction *current_transaction;
};


struct twopence_pipe_ops {
  int		(*open)(struct twopence_pipe_target *);
  int		(*recv)(struct twopence_pipe_target *, int, char *buffer, size_t count);
  int		(*send)(struct twopence_pipe_target *, int, const char *buffer, size_t count);
};

extern void	twopence_pipe_target_init(struct twopence_pipe_target *, int plugin_type, const struct twopence_plugin *,
			const struct twopence_pipe_ops *);

extern int	twopence_pipe_run_test(struct twopence_target *, twopence_command_t *, twopence_status_t *);
extern int	twopence_pipe_inject_file (struct twopence_target *, twopence_file_xfer_t *, twopence_status_t *);
extern int	twopence_pipe_extract_file (struct twopence_target *, twopence_file_xfer_t *, twopence_status_t *);
extern int	twopence_pipe_interrupt_command(struct twopence_target *);
extern int	twopence_pipe_exit_remote(struct twopence_target *);
extern void	twopence_pipe_end(struct twopence_target *);

#endif /* PIPE_H */
