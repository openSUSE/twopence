/*
Test executor, chroot plugin.

Copyright (C) 2016 SUSE

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

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>

#include "twopence.h"
#include "pipe.h"



struct twopence_chroot_target {
  struct twopence_pipe_target pipe;

  char *directory;
  pid_t child_pid;
};

extern const struct twopence_plugin twopence_chroot_ops;
extern const struct twopence_pipe_ops twopence_chroot_link_ops;

///////////////////////////// Lower layer ///////////////////////////////////////

/*
 * Initialize the handle
 *
 * Returns 0 if everything went fine, or -1 in case of error
 */
static int
__twopence_chroot_init(struct twopence_chroot_target *target, const char *directory)
{
  memset(target, 0, sizeof(*target));

  if (directory != NULL && getuid() != 0 && geteuid() != 0) {
   twopence_log_error("Cannot create chroot target with directory \"%s\" - insufficient privileges", directory);
   return TWOPENCE_INVALID_TARGET_ERROR;
  }

  twopence_pipe_target_init(&target->pipe, TWOPENCE_PLUGIN_CHROOT, &twopence_chroot_ops, &twopence_chroot_link_ops);

  if (directory)
    target->directory = twopence_strdup(directory);

  return 0;
}

/*
 * Fork the chroot worker, and establish the socket pair connecting us to it.
 *
 * Returns the file descriptor if successful, or -1 if failed
 */
static twopence_sock_t *
__twopence_chroot_open(struct twopence_pipe_target *pipe_handle)
{
  struct twopence_chroot_target *handle = (struct twopence_chroot_target *) pipe_handle;
  twopence_sock_t *ret_socket = NULL;
  sigset_t mask, omask;
  pid_t pid;
  int fd[2];

  if (socketpair(PF_UNIX, SOCK_STREAM, 0, fd) < 0) {
    twopence_log_error("Unable to create Unix socketpair: %m");
    return NULL;
  }

  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  sigprocmask(SIG_BLOCK, &mask, &omask);

  pid = fork();
  if (pid < 0) {
    twopence_log_error("Unable to fork chroot helper process: %m");
    goto out_reset_mask;
  }

  if (pid == 0) {
    static const unsigned int MAX_ARGC = 15;
    const char *server_path;
    char *argv[MAX_ARGC + 1];
    int argc = 0, i;

    argv[argc++] = "twopence_test_server";
    if (handle->directory) {
      argv[argc++] = "--root-directory";
      argv[argc++] = handle->directory;
    }

    argv[argc++] = "--port-stdio";
    for (i = 0; i < twopence_debug_level && argc < MAX_ARGC; ++i)
	    argv[argc++] = "--debug";
    argv[argc++] = NULL;

    close(fd[0]);
    dup2(fd[1], 0);

    server_path = getenv("TWOPENCE_SERVER_PATH");
    if (server_path) {
      execv(server_path, argv);
    } else {
      execvp(argv[0], argv);
    }

    twopence_log_error("Unable to execute twopence server: %m");
    exit(127);
  }

  handle->child_pid = pid;
  close(fd[1]);

  ret_socket = twopence_sock_new(fd[0]);

out_reset_mask:
  sigprocmask(SIG_SETMASK, &omask, NULL);
  return ret_socket;
}

const struct twopence_pipe_ops twopence_chroot_link_ops = {
  .open = __twopence_chroot_open,
};


///////////////////////////// Public interface //////////////////////////////////

//////////////////////////////////////////////////////////////////
// Initialize the library
//
// This specific plugin takes a directory name as argument
//
// Returns a "handle" that must be passed to subsequent function calls,
// or NULL in case of a problem
//////////////////////////////////////////////////////////////////
static struct twopence_target *
twopence_chroot_init(const char *filename)
{
  struct twopence_chroot_target *handle;

  // Allocate the opaque handle
  handle = twopence_calloc(1, sizeof(struct twopence_chroot_target));
  if (handle == NULL)
    return NULL;

  // Initialize the handle
  if (__twopence_chroot_init(handle, filename) < 0) {
    free(handle);
    return NULL;
  }

  return (struct twopence_target *) handle;
};

static struct twopence_target *
twopence_local_init(const char *param)
{
  struct twopence_chroot_target *handle;

  handle = twopence_calloc(1, sizeof(struct twopence_chroot_target));
  if (handle == NULL)
    return NULL;

  if (__twopence_chroot_init(handle, NULL) < 0) {
    free(handle);
    return NULL;
  }

  return (struct twopence_target *) handle;
};

/*
 * Define the plugin ops vector
 */
const struct twopence_plugin twopence_chroot_ops = {
	.name		= "chroot",

	.init = twopence_chroot_init,
	.set_option = twopence_pipe_set_option,
	.run_test = twopence_pipe_run_test,
	.wait = twopence_pipe_wait,
	.chat_send = twopence_pipe_chat_send,
	.chat_recv = twopence_pipe_chat_recv,
	.inject_file = twopence_pipe_inject_file,
	.extract_file = twopence_pipe_extract_file,
	.exit_remote = twopence_pipe_exit_remote,
	.interrupt_command = twopence_pipe_interrupt_command,
	.disconnect = twopence_pipe_disconnect,
	.end = twopence_pipe_end,
};

const struct twopence_plugin twopence_local_ops = {
	.name		= "local",

	.init = twopence_local_init,
	.set_option = twopence_pipe_set_option,
	.run_test = twopence_pipe_run_test,
	.wait = twopence_pipe_wait,
	.chat_send = twopence_pipe_chat_send,
	.chat_recv = twopence_pipe_chat_recv,
	.inject_file = twopence_pipe_inject_file,
	.extract_file = twopence_pipe_extract_file,
	.exit_remote = twopence_pipe_exit_remote,
	.interrupt_command = twopence_pipe_interrupt_command,
	.disconnect = twopence_pipe_disconnect,
	.end = twopence_pipe_end,
};
