/*
Test executor, virtio plugin.
It is used to send tests to QEmu/KVM virtual machines using virtio.


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

#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>

#define BUFFER_SIZE 32768              // Size in bytes of the work buffer for receiving data from the remote
#define TIMEOUT 5000                   // Timeout in milliseconds
#define LONG_TIMEOUT 60000             // Timeout that is big enough for a command to run without any output
#define UNIX_PATH_MAX 108              // Value correct for Linux only; used in /usr/include/sys/un.h

// This structure encapsulates in an opaque way the behaviour of the library
// It is not 100% opaque because it is publicly known that the first field is the plugin type
struct _twopence_opaque
{
  int type;                            // 0 for virtio
  enum { no_output, to_screen, common_buffer, separate_buffers } output_mode;
  char *buffer_out, *end_out;
  char *buffer_err, *end_err;
  struct sockaddr_un address;
};

///////////////////////////// Lower layer ///////////////////////////////////////

// Init the address in the handle
//
// Returns 0 if everything went fine, or -1 in case of error
int _twopence_init_handle(struct _twopence_opaque *handle, const char *sockname)
{
  // Store the plugin type
  handle->type = 0;                    // virtio

  handle->address.sun_family =         // UNIX domain sockets
    AF_LOCAL;
                                       // Copy the socket's filename if not too long
  if (strlen(sockname) >= UNIX_PATH_MAX)
    return -1;
  strcpy(handle->address.sun_path, sockname);
  return 0;
}

// Open the UNIX domain socket
//
// Returns the file descriptor if successful, or -1 if failed
int _twopence_open_link(const struct _twopence_opaque *handle)
{
  int socket_fd, flags;

  // Create the file descriptor
  socket_fd = socket(PF_LOCAL, SOCK_STREAM, AF_UNIX);
  if (socket_fd <= 0)
    return -1;

  // Make it non-blocking and not inheritable
  flags = fcntl(socket_fd, F_GETFL, 0);
  if (flags == -1) return -1;
  if (fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK) == -1)
    return -1;
  flags = fcntl(socket_fd, F_GETFD);
  if (flags == -1) return -1;
  if (fcntl(socket_fd, F_SETFD, flags | FD_CLOEXEC) == -1)
    return -1;

  // Open the connection
  if (connect(socket_fd,
              (const struct sockaddr *) &handle->address,
              sizeof(struct sockaddr_un)))
  {
    close(socket_fd);
    return -1;
  }

  return socket_fd;
}

// Receive a maximum amount of bytes from the socket into a buffer
//
// Returns the number of bytes received, -1 otherwise
int _twopence_receive_buffer
  (int socket_fd, char *buffer, int maximum, int *rc)
{
  struct pollfd fds[1];
  int n, size;

  *rc = 0;

  fds[0].fd = socket_fd;               // Wait either for input on the socket or for a timeout
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
    size = recv
      (socket_fd, buffer, maximum, 0);
    if (size < 0 && errno != EAGAIN)
    {
      *rc = errno;
      return -1;
    }
    return size;
  }

  return 0;
}

// Receive a maximum amount of bytes from the socket or from stdin into a buffer
//
// Returns the number of bytes received, -1 otherwise
int _twopence_receive_buffer_2
  (int socket_fd, char *buffer, int maximum, int *rc, bool *end_of_stdin)
{
  struct pollfd fds[2];
  int n, size;

  *rc = 0;

  fds[0].fd = 0;                       // Wait either for input on the keyboard, for input from the socket, or for a timeout
  fds[0].events = POLLIN;
  fds[1].fd = socket_fd;
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

  if (fds[1].revents & POLLIN)         // Receive a chunk of data on the socket
  {
    size = recv
      (socket_fd, buffer, maximum, 0);
    if (size < 0 && errno != EAGAIN)
    {
      *rc = errno;
      return -1;
    }
    if (size > 0) return size;
  }

  return 0;
}

// Send a number of bytes in a buffer to the socket
//
// Returns the number of bytes sent, or -1 in case of error
int _twopence_send_buffer
  (int socket_fd, char *buffer, int size)
{
  struct pollfd fds[1];
  int n, sent;

  fds[0].fd = socket_fd;               // Wait either for output possible on the socket or for a timeout
  fds[0].events = POLLOUT;
  n = poll(fds, 1, TIMEOUT);
  if (n <= 0)
    return -1;

  sent = 0;                            // Send the data
  if (fds[0].revents & POLLOUT)
  {
    sent = send
      (socket_fd, buffer, size, 0);
    if (sent < 0)
      return -1;
  }
  return sent;
}

///////////////////////////// Public interface //////////////////////////////////

// Initialize the library
//
// This specific plugin takes the filename of a UNIX domain socket as argument
//
// Returns a "handle" that must be passed to subsequent function calls,
// or NULL in case of a problem
void *twopence_init(const char *filename)
{
  struct _twopence_opaque *handle;

  // Allocate the opaque handle
  handle = malloc(sizeof(struct _twopence_opaque));
  if (handle == NULL) return NULL;

  // Store the plugin type
  handle->type = 0;                    // virtio

  // Initialize the handle
  if (_twopence_init_handle(handle, filename) < 0)
  {
    free(handle);
    return NULL;
  }

  return (void *) handle;
};

