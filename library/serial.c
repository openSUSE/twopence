/*
Test executor, serial plugin.
It is used to send tests to real machines using serial cables.


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

#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <poll.h>
#include <termios.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>

#include "twopence.h"
#include "protocol.h"

struct twopence_serial_target {
  struct twopence_pipe_target pipe;

  char device_path[PATH_MAX];
};

extern const struct twopence_plugin twopence_serial_ops;
extern const struct twopence_pipe_ops twopence_serial_link_ops;

///////////////////////////// Lower layer ///////////////////////////////////////

// Initialize the handle
//
// Returns 0 if everything went fine, or -1 in case of error
static int
__twopence_serial_init(struct twopence_serial_target *handle, const char *devname)
{
  twopence_pipe_target_init(&handle->pipe, TWOPENCE_PLUGIN_SERIAL, &twopence_serial_ops, &twopence_serial_link_ops);

  // Initialize the device name
  // FIXME: use PATH_MAX
  if (strlen(devname) >= PATH_MAX)
    return -1;
  strcpy(handle->device_path, devname);

  return 0;
}

// Open the UNIX character device
//
// Returns the file descriptor if successful, or -1 if failed
static int
__twopence_serial_open(struct twopence_pipe_target *pipe_handle)
{
  struct twopence_serial_target *handle = (struct twopence_serial_target *) pipe_handle;
  int device_fd;
  struct termios tio;

  // Create the file descriptor
  device_fd = open(handle->device_path, O_RDWR | O_NONBLOCK | O_CLOEXEC | O_NOCTTY);
  if (device_fd <= 0)
    return -1;

  // Set up serial line
  if (isatty(device_fd))
  {
    bzero(&tio, sizeof(struct termios));
    tio.c_cflag = CRTSCTS | CS8 | CLOCAL | CREAD;
    tio.c_iflag = 0;
    tio.c_oflag = 0;
    tio.c_lflag = 0;
    if (cfsetspeed(&tio, B115200) < 0)
      return -1;
    if (tcsetattr(device_fd, TCSANOW, &tio) < 0)
      return -1;
  }

  return device_fd;
}

// Receive a maximum amount of bytes from the device into a buffer
//
// Returns the number of bytes received, -1 otherwise
static int
__twopence_serial_recv(struct twopence_pipe_target *pipe_handle, int device_fd, char *buffer, size_t size)
{
  return read(device_fd, buffer, size);
}

// Send a number of bytes in a buffer to the device
//
// Returns the number of bytes sent, or -1 in case of error
static int
__twopence_serial_send(struct twopence_pipe_target *pipe_handle, int device_fd, const char *buffer, size_t size)
{
  return write(device_fd, buffer, size);
}

const struct twopence_pipe_ops twopence_serial_link_ops = {
  .open = __twopence_serial_open,
  .recv = __twopence_serial_recv,
  .send = __twopence_serial_send,
};

///////////////////////////// Public interface //////////////////////////////////

// Initialize the library
//
// This specific plugin takes the filename of a UNIX character device as argument
//
// Returns a "handle" that must be passed to subsequent function calls,
// or NULL in case of a problem
static struct twopence_target *
twopence_serial_init(const char *filename)
{
  struct twopence_serial_target *handle;

  // Allocate the opaque handle
  handle = calloc(1, sizeof(struct twopence_serial_target));
  if (handle == NULL) return NULL;

  // Initialize the handle
  if (__twopence_serial_init(handle, filename) < 0) {
    free(handle);
    return NULL;
  }

  return (struct twopence_target *) handle;
};

/*
 * Define the plugin ops vector
 */
const struct twopence_plugin twopence_serial_ops = {
	.name		= "serial",

	.init = twopence_serial_init,
	.run_test = twopence_pipe_run_test,
	.inject_file = twopence_pipe_inject_file,
	.extract_file = twopence_pipe_extract_file,
	.exit_remote = twopence_pipe_exit_remote,
	.interrupt_command = twopence_pipe_interrupt_command,
	.end = twopence_pipe_end,
};
