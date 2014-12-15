/*
Test executor, serial plugin.
It is used to send tests to real machines using serial cables.


Copyright (C) 2014 SUSE

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

#include "twopence.h"
#include "protocol.h"

#define BUFFER_SIZE 32768              // Size in bytes of the work buffer for receiving data from the remote
#define TIMEOUT 5000                   // Timeout in milliseconds
#define LONG_TIMEOUT 60000             // Timeout that is big enough for a command to run without any output

// This structure encapsulates in an opaque way the behaviour of the library
// It is not 100 % opaque, because it is publicly known that the first field is the plugin type
struct twopence_serial_target {
  struct twopence_pipe_target pipe;

  char device_path[PATH_MAX];
};

extern const struct twopence_plugin twopence_serial_ops;

///////////////////////////// Lower layer ///////////////////////////////////////

// Initialize the handle
//
// Returns 0 if everything went fine, or -1 in case of error
static int
__twopence_serial_init(struct twopence_serial_target *handle, const char *devname)
{
  twopence_pipe_target_init(&handle->pipe, TWOPENCE_PLUGIN_SERIAL, &twopence_serial_ops);

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
int _twopence_open_link(const struct twopence_serial_target *handle)
{
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
int _twopence_receive_buffer
  (int device_fd, char *buffer, int maximum, int *rc)
{
  struct pollfd fds[1];
  int n, size;

  *rc = 0;

  fds[0].fd = device_fd;               // Wait either for input on the device or for a timeout
  fds[0].events = POLLIN;
  n = poll(fds, 1, TIMEOUT);
  if (n < 0)
  {
    *rc = errno;
    return -1;
  }
  if (n == 0)
  {
    *rc = ETIME;
    return -1;
  }

  if (fds[0].revents & POLLIN)         // Read the data
  {
    size = read
      (device_fd, buffer, maximum, 0);
    if (size < 0 && errno != EAGAIN)
    {
      *rc = errno;
      return -1;
    }
    return size;
  }

  return 0;
}

// Receive a maximum amount of bytes from the device or from stdin into a buffer
//
// Returns the number of bytes received, -1 otherwise
int _twopence_receive_buffer_2
  (int device_fd, char *buffer, int maximum, int *rc, bool *end_of_stdin)
{
  struct pollfd fds[2];
  int n, size;

  *rc = 0;

  fds[0].fd = 0;                       // Wait either for input on the keyboard, for input from the device, or for a timeout
  fds[0].events = POLLIN;
  fds[1].fd = device_fd;
  fds[1].events = POLLIN;
  if (*end_of_stdin)
    n = poll(fds + 1, 1, LONG_TIMEOUT);
  else
    n = poll(fds, 2, LONG_TIMEOUT);
  if (n < 0)
  {
    *rc = errno;
    return -1;
  }
  if (n == 0)
  {
    *rc = ETIME;
    return -1;
  }

  if (!*end_of_stdin)                  // If not end of input on stdin
  {
    if (fds[0].revents & POLLIN)       // Receive a chunk of data on real standard input
    {
      size = read
        (0, buffer + 4, BUFFER_SIZE - 4, 0);
      if (size < 0)
      {
        *rc = errno;
        return -1;
      }
      if (size > 0)
      {
        buffer[0] = '0';
        store_length(size + 4, buffer);
        return size + 4;
      }                                // Catch Ctrl-D at the beginning of line
      *end_of_stdin = true;            // We reached end of input
      buffer[0] = 'E';
      store_length(4, buffer);
      return 4;
    }
    else if (!isatty(0))               // Catch end of pipe as well
    {
      *end_of_stdin = true;            // We also reached end of input
      buffer[0] = 'E';
      store_length(4, buffer);
      return 4;
    }
  }

  if (fds[1].revents & POLLIN)         // Receive a chunk of data on the device
  {
    size = read
      (device_fd, buffer, maximum, 0);
    if (size < 0 && errno != EAGAIN)
    {
      *rc = errno;
      return -1;
    }
    if (size > 0) return size;
  }

  return 0;
}

// Send a number of bytes in a buffer to the device
//
// Returns the number of bytes sent, or -1 in case of error
int _twopence_send_buffer
  (int device_fd, char *buffer, int size)
{
  struct pollfd fds[1];
  int n, sent;

  fds[0].fd = device_fd;               // Wait either for output possible on the device or for a timeout
  fds[0].events = POLLOUT;
  n = poll(fds, 1, TIMEOUT);
  if (n <= 0)
    return -1;

  sent = 0;                            // Send the data
  if (fds[0].revents & POLLOUT)
  {
    sent = write
      (device_fd, buffer, size, 0);
    if (sent < 0)
      return -1;
  }
  return sent;
}

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
	.test_and_print_results	= twopence_pipe_test_and_print_results,
	.test_and_drop_results	= twopence_pipe_test_and_drop_results,
	.test_and_store_results_together = twopence_pipe_test_and_store_results_together,
	.test_and_store_results_separately = twopence_pipe_test_and_store_results_separately,
	.inject_file = twopence_pipe_inject_file,
	.extract_file = twopence_pipe_extract_file,
	.exit_remote = twopence_pipe_exit_remote,
	.interrupt_command = twopence_pipe_interrupt_command,
	.end = twopence_pipe_end,
};
