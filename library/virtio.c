/*
Test executor, virtio plugin.
It is used to send tests to QEmu/KVM virtual machines using virtio.


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

#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <unistd.h>

#include "twopence.h"
#include "pipe.h"

struct twopence_virtio_target {
  struct twopence_pipe_target pipe;

  struct sockaddr_un address;
};

extern const struct twopence_plugin twopence_virtio_ops;
extern const struct twopence_pipe_ops twopence_virtio_link_ops;

///////////////////////////// Lower layer ///////////////////////////////////////

// Initialize the handle
//
// Returns 0 if everything went fine, or -1 in case of error
static int
__twopence_virtio_init(struct twopence_virtio_target *handle, const char *sockname)
{
  twopence_pipe_target_init(&handle->pipe, TWOPENCE_PLUGIN_VIRTIO, &twopence_virtio_ops, &twopence_virtio_link_ops);

  // Initialize the socket address
  handle->address.sun_family = AF_LOCAL;
  if (strlen(sockname) >= sizeof(handle->address.sun_path))
    return -1;
  strcpy(handle->address.sun_path, sockname);

  return 0;
}

/*
 * Open the UNIX domain socket
 *
 * Returns the file descriptor if successful, or -1 if failed
 */
static twopence_sock_t *
__twopence_virtio_open(struct twopence_pipe_target *pipe_handle)
{
  struct twopence_virtio_target *handle = (struct twopence_virtio_target *) pipe_handle;
  int socket_fd;

  // Create the file descriptor
  socket_fd = socket(PF_LOCAL, SOCK_STREAM, AF_UNIX);
  if (socket_fd <= 0)
    return NULL;

  // Open the connection
  if (connect(socket_fd,
              (const struct sockaddr *) &handle->address,
              sizeof(struct sockaddr_un)))
  {
    close(socket_fd);
    return NULL;
  }

  /* Note, we do not pass O_NONBLOCK here, but we do set O_CLOEXEC */
  return twopence_sock_new_flags(socket_fd, O_RDWR | O_CLOEXEC);
}

const struct twopence_pipe_ops twopence_virtio_link_ops = {
  .open = __twopence_virtio_open,
};

///////////////////////////// Public interface //////////////////////////////////

// Initialize the library
//
// This specific plugin takes the filename of a UNIX domain socket as argument
//
// Returns a "handle" that must be passed to subsequent function calls,
// or NULL in case of a problem
static struct twopence_target *
twopence_virtio_init(const char *filename)
{
  struct twopence_virtio_target *handle;

  // Allocate the opaque handle
  handle = calloc(1, sizeof(struct twopence_virtio_target));
  if (handle == NULL)
    return NULL;

  // Initialize the handle
  if (__twopence_virtio_init(handle, filename) < 0) {
    free(handle);
    return NULL;
  }

  return (struct twopence_target *) handle;
};

/*
 * Define the plugin ops vector
 */
const struct twopence_plugin twopence_virtio_ops = {
	.name		= "virtio",

	.init = twopence_virtio_init,
	.run_test = twopence_pipe_run_test,
	.wait = twopence_pipe_wait,
	.inject_file = twopence_pipe_inject_file,
	.extract_file = twopence_pipe_extract_file,
	.exit_remote = twopence_pipe_exit_remote,
	.interrupt_command = twopence_pipe_interrupt_command,
	.end = twopence_pipe_end,
};
