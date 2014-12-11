/*
Test executor, virtio and serial plugins
(the ones that use a custom protocol to communicate with the remote host).


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

#include <sys/stat.h>
#include <stdio.h>                     // For snprintf() parsing facility. Most I/O is low-level and unbuffered.
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>

#include "twopence.h"

#define BUFFER_SIZE 32768              // Size in bytes of the work buffer for receiving data from the remote
#define COMMAND_BUFFER_SIZE 8192       // Size in bytes of the work buffer for sending data to the remote

// This structure encapsulates in an opaque way the behaviour of the library
// It is not 100 % opaque, because it is publicly known that the first field is the plugin type
struct _twopence_opaque
{
  int type;
  enum { no_output, to_screen, common_buffer, separate_buffers } output_mode;
  char *buffer_out, *end_out;
  char *buffer_err, *end_err;
  // More fields here according to real type
  // Yes, this is class inheritance written in C...
};

///////////////////////////// Lower layer ///////////////////////////////////////

// Tune stdin to be blocking or nonblocking
//
// Returns 0 if everything went fine, or -1 if failed
int _twopence_tune_stdin(bool blocking)
{
  int flags;

  flags = fcntl(0, F_GETFL, 0);        // Get old flags
  if (flags == -1) return -1;
  flags = blocking?                    // Set new flags
          flags & ~O_NONBLOCK:
          flags | O_NONBLOCK;
  if (fcntl(0, F_SETFL, flags) == -1)
    return -1;
}

// Store length of data chunk to send
void store_length(int length, char *buffer)
{
  buffer[2] = (length & 0xFF00) >> 8;
  buffer[3] = length & 0xFF;
}

// Compute length of data chunk received
int compute_length(const unsigned char *buffer)
{
  unsigned int high = buffer[2],
               low = buffer[3];
  return (high << 8) | low;
}

// Output a "stdout" character through one of the available methods
//
// Returns 0 if everything went fine, -1 otherwise
int _twopence_output
  (struct _twopence_opaque *handle, char c)
{
  int written;

  switch (handle->output_mode)
  {
    case no_output:
      break;
    case to_screen:
      written = write(1, &c, 1);
      if (written != 1) return -1;
      break;
    case separate_buffers:
    case common_buffer:
      if (handle->buffer_out >= handle->end_out)
        return -1;
      *handle->buffer_out++ = c;
      break;
    default:
      return -1;
  }
  return 0;
}

// Output a "stderr" character through one of the available methods
//
// Returns 0 if everything went fine, -1 otherwise
int _twopence_error
  (struct _twopence_opaque *handle, char c)
{
  int written;

  switch (handle->output_mode)
  {
    case no_output:
      break;
    case to_screen:
      written = write(2, &c, 1);
      if (written != 1) return -1;
      break;
    case separate_buffers:
      if (handle->buffer_err >= handle->end_err)
        return -1;
      *handle->buffer_err++ = c;
      break;
    case common_buffer:
      if (handle->buffer_out >= handle->end_out)
        return -1;
      *handle->buffer_out++ = c;
      break;
    default:
      return -1;
  }
  return 0;
}

// Check for invalid usernames
bool _twopence_invalid_username(const char *username)
{
  const char *p;

  for (p = username; *p; p++)
  {
    if ('0' <= *p && *p <= '9') continue;
    if ('A' <= *p && *p <= 'Z') continue;
    if ('a' <= *p && *p <= 'z') continue;
    if (*p == '_') continue;
    return true;
  }

  return false;
}

// Send a number of bytes in a buffer to the device
// Send it in several times to accomodate for slow lines
//
// Returns true if everything went fine, false otherwise
bool _twopence_send_big_buffer
  (int device_fd, char *buffer, int size)
{
  int sent;

  while (size > 0)
  {
    sent = _twopence_send_buffer
      (device_fd, buffer, size);
    if (sent == -1) return false;

    buffer += sent;
    size -= sent;
  }

  return size == 0;
}

///////////////////////////// Middle layer //////////////////////////////////////

// Read a chunk from the link
//
// Returns 0 when everything went fine,
// a Linux error code otherwise.
int _twopence_read_chunk(int link_fd, char *buffer)
{
  int remaining;
  char *p;
  int rc, size, length;

  remaining = 4;                       // First try to read the header
  p = buffer;
  while (remaining > 0)
  {
    size = _twopence_receive_buffer    // Receive less than the remaining amount of data
      (link_fd, p, remaining, &rc);
    if (size < 0)
      return rc;

    remaining -= size;
    p += size;
  }

  length = compute_length(buffer);     // Decode the announced amount of data
  if (length > BUFFER_SIZE)
    return ENOMEM;

  remaining = length - 4;              // Read the announced amount of data
  while (remaining > 0)
  {
    size = _twopence_receive_buffer    // Receive less than the remaining amount of data
      (link_fd, p, remaining, &rc);
    if (size < 0)
      return rc;

    remaining -= size;
    p += size;
  }

  return 0;
}

// Read a chunk from the link or from the standard input
//
// Returns 0 when everything went fine,
// a Linux error code otherwise.
int _twopence_read_chunk_2(int link_fd, char *buffer, bool *end_of_stdin)
{
  int remaining;
  char *p;
  int rc, size, length;

  remaining = 4;                       // First try to read the header
  p = buffer;
  while (remaining > 0)
  {
    size = _twopence_receive_buffer_2  // Receive less than the remaining amount of data
      (link_fd, p, remaining, &rc, end_of_stdin);
    if (size < 0)
      return rc;

    remaining -= size;
    p += size;
  }

  if (buffer[0] == '0' ||              // If that was input on stdin, we're done
      buffer[0] == 'E') return 0;

  length = compute_length(buffer);     // Decode the announced amount of data
  if (length > BUFFER_SIZE)
    return ENOMEM;

  remaining = length - 4;              // Read the announced amount of data
  while (remaining > 0)
  {
    size = _twopence_receive_buffer    // Receive less than the remaining amount of data
      (link_fd, p, remaining, &rc);
    if (size < 0)
      return rc;

    remaining -= size;
    p += size;
  }

  return 0;
}

// Read stdin, stdout, stderr, and both error codes
//
// Returns 0 if everything went fine, or a negative error code if failed
int _twopence_read_results
  (struct _twopence_opaque *handle, int link_fd, int *major, int *minor)
{
  int state;                           // 0 = processing results, 1 = major received, 2 = minor received
  bool end_of_stdin;
  char buffer[BUFFER_SIZE];
  int rc, received, sent;
  const char *p;

  state = 0;
  end_of_stdin = false;
  while (state != 2)
  {
    rc = _twopence_read_chunk_2        // Receive a chunk of data
      (link_fd, buffer, &end_of_stdin);
    if (rc != 0)
      return TWOPENCE_RECEIVE_RESULTS_ERROR;
    received = compute_length(buffer);

    switch (buffer[0])                 // Parse received data
    {
      case '0':                        // stdin
      case 'E':                        // End of file on stdin
        if (state != 0)
          return TWOPENCE_FORWARD_INPUT_ERROR;
        sent = _twopence_send_buffer   // Forward it to the system under test
          (link_fd, buffer, received);
        if (sent != received)
          return TWOPENCE_FORWARD_INPUT_ERROR;
        break;

      case '1':                        // stdout
        if (state != 0)
          return TWOPENCE_RECEIVE_RESULTS_ERROR;
        for (p = buffer + 4; received > 4; received--)
        {                              // Output it
          if (_twopence_output(handle, *p++) < 0)
            return TWOPENCE_RECEIVE_RESULTS_ERROR;
        }
        break;

      case '2':                        // stderr
        if (state != 0)
          return TWOPENCE_RECEIVE_RESULTS_ERROR;
        for (p = buffer + 4; received > 4; received--)
        {                              // Output it
          if (_twopence_error(handle, *p++) < 0)
            return TWOPENCE_RECEIVE_RESULTS_ERROR;
        }
        break;

      case 'M':                        // Major error code
        if (state != 0)
          return TWOPENCE_RECEIVE_RESULTS_ERROR;
        state = 1;
        sscanf(buffer + 4, "%d", major);
        break;

      case 'm':                        // Minor error code
        if (state != 1)
          return TWOPENCE_RECEIVE_RESULTS_ERROR;
        state = 2;
        sscanf(buffer + 4, "%d", minor);
        break;

      default:
        return TWOPENCE_RECEIVE_RESULTS_ERROR;
    }
  }

  return 0;
}

// Read major error code
//
// Returns 0 if everything went fine, or a negative error code if failed
int _twopence_read_major
  (int link_fd, int *major)
{
  char buffer[BUFFER_SIZE];
  int rc, received;

  rc = _twopence_read_chunk            // Receive a chunk of data
    (link_fd, buffer);
  if (rc != 0)
    return TWOPENCE_RECEIVE_FILE_ERROR;

  if (buffer[0] != 'M')                // Analyze the header
    return TWOPENCE_RECEIVE_FILE_ERROR;
  sscanf(buffer + 4, "%d", major);

  return 0;
}

// Read minor error code
//
// Returns 0 if everything went fine, or a negative error code if failed
int _twopence_read_minor
  (int link_fd, int *minor)
{
  char buffer[BUFFER_SIZE];
  int rc, received;

  rc = _twopence_read_chunk            // Receive a chunk of data
    (link_fd, buffer);
  if (rc != 0)
    return TWOPENCE_RECEIVE_FILE_ERROR;

  if (buffer[0] != 'm')                // Analyze the header
    return TWOPENCE_RECEIVE_FILE_ERROR;
  sscanf(buffer + 4, "%d", minor);

  return 0;
}

// Read file size
// It can also get a remote error code if, for example, the remote file does not exist
//
// Returns 0 if everything went fine, or a negative error code if failed
int _twopence_read_size
  (int link_fd, int *size, int *remote_rc)
{
  char buffer[BUFFER_SIZE];
  int rc, received;

  rc = _twopence_read_chunk            // Receive a chunk of data
    (link_fd, buffer);
  if (rc != 0)
    return TWOPENCE_RECEIVE_FILE_ERROR;

  switch (buffer[0])                   // Analyze the header
  {
    case 's':
      sscanf(buffer + 4, "%d", size);
      break;
    case 'M':
      sscanf(buffer + 4, "%d", remote_rc);
      break;
    default:
      return TWOPENCE_RECEIVE_FILE_ERROR;
  }

  return 0;
}

// Send a file in chunks to the link
//
// Returns 0 if everything went fine, or a negative error code if failed
int _twopence_send_file
  (struct _twopence_opaque *handle, int file_fd, int link_fd, int remaining)
{
  char buffer[BUFFER_SIZE];
  int size, received;

  while (remaining > 0)
  {
    size =                             // Read at most BUFFER_SIZE - 4 bytes from the file
           remaining < BUFFER_SIZE - 4?
           remaining:
           BUFFER_SIZE - 4;
    received = read(file_fd, buffer + 4, size);
    if (received != size)
    {
      _twopence_output(handle, '\n');
      return TWOPENCE_LOCAL_FILE_ERROR;
    }

    buffer[0] = 'd';                   // Send them to the remote host, together with 4 bytes of header
    store_length(received + 4, buffer);
    if (!_twopence_send_big_buffer
      (link_fd, buffer, received + 4))
    {
      _twopence_output(handle, '\n');
      return TWOPENCE_SEND_FILE_ERROR;
    }

    _twopence_output(handle, '.');     // Progression dots
    remaining -= received;             // One chunk less to send
  }
  _twopence_output(handle, '\n');
  return 0;
}

// Receive a file in chunks from the link and write it to a file
//
// Returns 0 if everything went fine, or a negative error code if failed
int _twopence_receive_file
  (struct _twopence_opaque *handle, int file_fd, int link_fd, int remaining)
{
  char buffer[BUFFER_SIZE];
  int rc, received, written;

  while (remaining > 0)
  {
    rc = _twopence_read_chunk          // Receive a chunk of data
      (link_fd, buffer);
    if (rc != 0)
    {
      _twopence_output(handle, '\n');
      return TWOPENCE_RECEIVE_FILE_ERROR;
    }

    received =                         // Analyze the header
      compute_length(buffer) - 4;
    if (buffer[0] != 'd' || received < 0 || received > remaining)
    {
      _twopence_output(handle, '\n');
      return TWOPENCE_RECEIVE_FILE_ERROR;
    }

    if (received > 0)
    {
      written = write                  // Write the data to the file
        (file_fd, buffer + 4, received);
      if (written != received)
      {
        _twopence_output(handle, '\n');
        return TWOPENCE_LOCAL_FILE_ERROR;
      }
      _twopence_output(handle, '.');   // Progression dots
      remaining -= received;           // One chunk less to write
    }
  }
  _twopence_output(handle, '\n');
  return 0;
}

///////////////////////////// Top layer /////////////////////////////////////////

// Send a Linux command to the remote host
//
// Returns 0 if everything went fine, or a negative error code if failed
int _twopence_command_virtio_serial
  (struct _twopence_opaque *handle, const char *username, const char *linux_command, int *major, int *minor)
{
  char command[COMMAND_BUFFER_SIZE];
  int n;
  int link_fd;
  int sent, rc;

  // By default, no major and no minor
  *major = 0;
  *minor = 0;

  // Check that the username is valid
  if (_twopence_invalid_username(username))
    return TWOPENCE_PARAMETER_ERROR;

  // Refuse to execute empty commands
  if (*linux_command == '\0')
    return TWOPENCE_PARAMETER_ERROR;

  // Prepare command to send to the remote host
  n = snprintf(command, COMMAND_BUFFER_SIZE,
               "c...%s %s", username, linux_command);
  if (n < 0 || n >= COMMAND_BUFFER_SIZE)
    return TWOPENCE_PARAMETER_ERROR;
  store_length(n + 1, command);

  // Tune stdin so it is nonblocking
  if (_twopence_tune_stdin(false) < 0)
    return TWOPENCE_OPEN_SESSION_ERROR;

  // Open communication link
  link_fd = _twopence_open_link(handle);
  if (link_fd < 0)
  {
    _twopence_tune_stdin(true);
    return TWOPENCE_OPEN_SESSION_ERROR;
  }

  // Send command (including terminating NUL)
  sent = _twopence_send_buffer
           (link_fd, command, n + 1);
  if (sent != n + 1)
  {
    _twopence_tune_stdin(true);
    close(link_fd);
    return TWOPENCE_SEND_COMMAND_ERROR;
  }

  // Read "standard output" and "standard error"
  rc = _twopence_read_results(handle, link_fd, major, minor);
  if (rc < 0)
  {
    _twopence_tune_stdin(true);
    close(link_fd);
    return TWOPENCE_RECEIVE_RESULTS_ERROR;
  }

  _twopence_tune_stdin(true);
  close(link_fd);
  return 0;
}

// Inject a file into the remote host
//
// Returns 0 if everything went fine
int _twopence_inject_virtio_serial
  (struct _twopence_opaque *handle, const char *username, int file_fd, const char *remote_filename, int *remote_rc)
{
  char command[COMMAND_BUFFER_SIZE];
  int n;
  int link_fd;
  int sent, rc;
  struct stat filestats;
  char byte1, byte2;

  // By default, no remote error
  *remote_rc = 0;

  // Check that the username is valid
  if (_twopence_invalid_username(username))
    return TWOPENCE_PARAMETER_ERROR;

  // Prepare command to send to the remote host
  fstat(file_fd, &filestats);
  n = snprintf(command, COMMAND_BUFFER_SIZE,
               "i...%s %ld %s", username, (long) filestats.st_size, remote_filename);
  if (n < 0 || n >= COMMAND_BUFFER_SIZE)
    return TWOPENCE_PARAMETER_ERROR;
  store_length(n + 1, command);

  // Open communication link
  link_fd = _twopence_open_link(handle);
  if (link_fd < 0)
    return TWOPENCE_OPEN_SESSION_ERROR;

  // Send command (including terminating NUL)
  sent = _twopence_send_buffer
           (link_fd, command, n + 1);
  if (sent != n + 1)
  {
    close(link_fd);
    return TWOPENCE_SEND_COMMAND_ERROR;
  }

  // Read first return code before we start transferring the file
  // This enables to detect a remote problem even before we start the transfer
  rc = _twopence_read_major
         (link_fd, remote_rc);
  if (*remote_rc != 0)
  {
    close(link_fd);
    return TWOPENCE_SEND_FILE_ERROR;
  }

  // Send the file
  rc = _twopence_send_file(handle, file_fd, link_fd, filestats.st_size);
  if (rc < 0)
  {
    close(link_fd);
    return TWOPENCE_SEND_FILE_ERROR;
  }

  // Read second return code from remote
  rc = _twopence_read_minor
         (link_fd, remote_rc);
  if (rc < 0)
  {
    close(link_fd);
    return TWOPENCE_SEND_FILE_ERROR;
  }

  close(link_fd);
  return 0;
}

// Extract a file from the remote host
//
// Returns 0 if everything went fine, or a negative error code if failed
int _twopence_extract_virtio_serial
  (struct _twopence_opaque *handle, const char *username, int file_fd, const char *remote_filename, int *remote_rc)
{
  char command[COMMAND_BUFFER_SIZE];
  int n;
  int link_fd;
  int sent, rc;
  int size;
  char byte1, byte2;

  // By default, no remote error
  *remote_rc = 0;

  // Check that the username is valid
  if (_twopence_invalid_username(username))
    return TWOPENCE_PARAMETER_ERROR;

  // Prepare command to send to the remote host
  n = snprintf(command, COMMAND_BUFFER_SIZE,
               "e...%s %s", username, remote_filename);
  if (n < 0 || n >= COMMAND_BUFFER_SIZE)
    return TWOPENCE_PARAMETER_ERROR;
  store_length(n + 1, command);

  // Open link for transmitting the command
  link_fd = _twopence_open_link(handle);
  if (link_fd < 0)
    return TWOPENCE_OPEN_SESSION_ERROR;

  // Send command (including terminating NUL)
  sent = _twopence_send_buffer
           (link_fd, command, n + 1);
  if (sent != n + 1)
  {
    close(link_fd);
    return TWOPENCE_SEND_COMMAND_ERROR;
  }

  // Read the size of the file to receive
  rc = _twopence_read_size(link_fd, &size, remote_rc);
  if (rc < 0)
  {
    close(link_fd);
    return TWOPENCE_RECEIVE_FILE_ERROR;
  }

  // Receive the file
  if (size >= 0)
  {
    rc = _twopence_receive_file(handle, file_fd, link_fd, size);
    if (rc < 0)
      return TWOPENCE_RECEIVE_FILE_ERROR;
  }

  close(link_fd);
  return 0;
}

// Tell the remote test server to exit
//
// Returns 0 if everything went fine, or a negative error code if failed
int _twopence_exit_virtio_serial
  (struct _twopence_opaque *handle)
{
  char command[COMMAND_BUFFER_SIZE];
  int n;
  int link_fd;
  int sent;

  // Prepare command to send to the remote host
  n = snprintf(command, COMMAND_BUFFER_SIZE,
               "q...");
  if (n < 0 || n >= COMMAND_BUFFER_SIZE)
    return TWOPENCE_PARAMETER_ERROR;
  store_length(n + 1, command);

  // Open link for sending exit command
  link_fd = _twopence_open_link(handle);
  if (link_fd < 0)
    return TWOPENCE_OPEN_SESSION_ERROR;

  // Send command (including terminating NUL)
  sent = _twopence_send_buffer
           (link_fd, command, n + 1);
  if (sent != n + 1)
  {
    close(link_fd);
    return TWOPENCE_SEND_COMMAND_ERROR;
  }

  close(link_fd);
  return 0;
}

// Interrupt current command
//
// Returns 0 if everything went fine, or a negative error code if failed
int _twopence_interrupt_virtio_serial
  (struct _twopence_opaque *handle)
{
  char command[COMMAND_BUFFER_SIZE];
  int n;
  int link_fd;
  int sent;

  // Prepare command to send to the remote host
  n = snprintf(command, COMMAND_BUFFER_SIZE,
               "I...");
  if (n < 0 || n >= COMMAND_BUFFER_SIZE)
    return TWOPENCE_PARAMETER_ERROR;
  store_length(n + 1, command);

  // Open link for sending interrupt command
  link_fd = _twopence_open_link(handle);
  if (link_fd < 0)
    return TWOPENCE_OPEN_SESSION_ERROR;

  // Send command (including terminating NUL)
  sent = _twopence_send_buffer
           (link_fd, command, n + 1);
  if (sent != n + 1)
  {
    close(link_fd);
    return TWOPENCE_INTERRUPT_COMMAND_ERROR;
  }

  close(link_fd);
  return 0;
}

///////////////////////////// Public interface //////////////////////////////////

// Run a test command, and print output
//
// Returns 0 if everything went fine
// 'major' is the return code of the test server
// 'minor' is the return code of the command
int twopence_test_and_print_results
  (struct twopence_target *opaque_handle, const char *username, const char *command,
   int *major, int *minor)
{
  struct _twopence_opaque *handle = (struct _twopence_opaque *) opaque_handle;

  handle->output_mode = to_screen;

  return _twopence_command_virtio_serial
           (handle, username, command, major, minor);
}

// Run a test command, and drop output
//
// Returns 0 if everything went fine
// 'major' is the return code of the test server
// 'minor' is the return code of the command
int twopence_test_and_drop_results
  (struct twopence_target *opaque_handle, const char *username, const char *command,
   int *major, int *minor)
{
  struct _twopence_opaque *handle = (struct _twopence_opaque *) opaque_handle;

  handle->output_mode = no_output;

  return _twopence_command_virtio_serial
           (handle, username, command, major, minor);
}

// Run a test command, and store the results in memory in a common buffer
//
// Returns 0 if everything went fine
// 'major' is the return code of the test server
// 'minor' is the return code of the command
int twopence_test_and_store_results_together
  (struct twopence_target *opaque_handle, const char *username, const char *command,
   char *buffer_out, int size,
   int *major, int *minor)
{
  struct _twopence_opaque *handle = (struct _twopence_opaque *) opaque_handle;
  int rc;

  handle->output_mode = common_buffer;
  handle->buffer_out = buffer_out; handle->end_out = buffer_out + size;

  rc = _twopence_command_virtio_serial
         (handle, username, command, major, minor);

  // Store final NUL
  if (rc == 0)
  {
    if (handle->buffer_out >= handle->end_out)
      rc = TWOPENCE_RECEIVE_RESULTS_ERROR;
    else
      *handle->buffer_out = '\0';
  }
  return rc;
}

// Run a test command, and store the results in memory in two separate buffers
//
// Returns 0 if everything went fine
// 'major' is the return code of the test server
// 'minor' is the return code of the command
int twopence_test_and_store_results_separately
  (struct twopence_target *opaque_handle, const char *username, const char *command,
   char *buffer_out, char *buffer_err, int size,
   int *major, int *minor)
{
  struct _twopence_opaque *handle = (struct _twopence_opaque *) opaque_handle;
  int rc;

  handle->output_mode = separate_buffers;
  handle->buffer_out = buffer_out; handle->end_out = buffer_out + size;
  handle->buffer_err = buffer_err; handle->end_err = buffer_err + size;

  rc = _twopence_command_virtio_serial
         (handle, username, command, major, minor);

  // Store final NULs
  if (rc == 0)
  {
    if (handle->buffer_out >= handle->end_out)
      rc = TWOPENCE_RECEIVE_RESULTS_ERROR;
    else
      *handle->buffer_out = '\0';
  }
  if (rc == 0)
  {
    if (handle->buffer_err >= handle->end_err)
      rc = TWOPENCE_RECEIVE_RESULTS_ERROR;
    else
      *handle->buffer_err = '\0';
  }
  return rc;
}

// Inject a file into the Virtual Machine
//
// Returns 0 if everything went fine
int twopence_inject_file
  (struct twopence_target *opaque_handle, const char *username,
   const char *local_filename, const char *remote_filename,
   int *remote_rc, bool dots)
{
  struct _twopence_opaque *handle = (struct _twopence_opaque *) opaque_handle;
  int fd, rc;

  handle->output_mode = dots? to_screen: no_output;

  // Open the file
  fd = open(local_filename, O_RDONLY);
  if (fd == -1)
    return errno == ENAMETOOLONG?
           TWOPENCE_PARAMETER_ERROR:
           TWOPENCE_LOCAL_FILE_ERROR;

  // Inject it
  rc = _twopence_inject_virtio_serial
         (handle, username, fd, remote_filename, remote_rc);
  if (rc == 0 && *remote_rc != 0)
    rc = TWOPENCE_REMOTE_FILE_ERROR;

  // Close it
  close(fd);
  return rc;
}

// Extract a file from the Virtual Machine
//
// Returns 0 if everything went fine
int twopence_extract_file
  (struct twopence_target *opaque_handle, const char *username,
   const char *remote_filename, const char *local_filename,
   int *remote_rc, bool dots)
{
  struct _twopence_opaque *handle = (struct _twopence_opaque *) opaque_handle;
  int fd, rc;

  handle->output_mode = dots? to_screen: no_output;

  // Open the file, creating it if it does not exist (u=rw,g=rw,o=)
  fd = creat(local_filename, 00660);
  if (fd == -1)
    return errno == ENAMETOOLONG?
           TWOPENCE_PARAMETER_ERROR:
           TWOPENCE_LOCAL_FILE_ERROR;

  // Extract it
  rc = _twopence_extract_virtio_serial
         (handle, username, fd, remote_filename, remote_rc);
  if (rc == 0 && *remote_rc != 0)
    rc = TWOPENCE_REMOTE_FILE_ERROR;

  // Close it
  close(fd);
  return rc;
}

// Interrupt current command
//
// Returns 0 if everything went fine
int twopence_interrupt_command(struct twopence_target *opaque_handle)
{
  struct _twopence_opaque *handle = (struct _twopence_opaque *) opaque_handle;

  return _twopence_interrupt_virtio_serial(handle);
}

// Tell the remote test server to exit
//
// Returns 0 if everything went fine
int twopence_exit_remote(struct twopence_target *opaque_handle)
{
  struct _twopence_opaque *handle = (struct _twopence_opaque *) opaque_handle;

  handle->output_mode = no_output;

  return _twopence_exit_virtio_serial(handle);
}

// Close the library
void twopence_end(struct twopence_target *opaque_handle)
{
  struct _twopence_opaque *handle = (struct _twopence_opaque *) opaque_handle;

  free(handle);
}
