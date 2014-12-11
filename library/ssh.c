/*
Test executor, ssh plugin.
It is used to send tests to real machines or VMs using SSH protocol.


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

#include <libssh/libssh.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <libgen.h>

#include <stdbool.h>
#include <string.h>
#include <malloc.h>

#include "twopence.h"

#define BUFFER_SIZE 16384              // Size in bytes of the work buffer for receiving data from the remote host
#define LONG_TIMEOUT 60                // Timeout (in seconds) that is big enough for a command to run without any output

// This structure encapsulates in an opaque way the behaviour of the library
// It is not 100 % opaque, because it is publicly known that the first field is the plugin type
struct twopence_ssh_target
{
  int type;
  enum { no_output, to_screen, common_buffer, separate_buffers } output_mode;
  char *buffer_out, *end_out;
  char *buffer_err, *end_err;
  ssh_session template,
              session;
  ssh_channel channel;                 // Set during remote command execution only
};

///////////////////////////// Lower layer ///////////////////////////////////////

// Tune stdin to be blocking or nonblocking
//
// Returns 0 if everything went fine, or -1 if failed.
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

// Output a "stdout" character through one of the available methods
//
// Returns 0 if everything went fine, a negative error code otherwise
int _twopence_output
  (struct twopence_ssh_target *handle, char c)
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
// Returns 0 if everything went fine, a negative error code otherwise
int _twopence_error
  (struct twopence_ssh_target *handle, char c)
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

// Process chunk of data sent by the remote host
//
// Returns 0 if everything went fine, a negative error code otherwise
int _twopence_process_chunk
  (struct twopence_ssh_target *handle, const char *buffer, int size, bool error)
{
  const char *end;
  int rc;

  for (end = buffer + size;
       buffer < end;
       buffer++)
  {
    if (error) rc = _twopence_error(handle, *buffer);
    else rc = _twopence_output(handle, *buffer);
    if (rc < 0) return -1;
  }
  return 0;
}

// Avoid active wait by sleeping
void _twopence_sleep()
{
  struct timespec t;

  t.tv_sec = 0;
  t.tv_nsec = 20000000L;               // 1/50th of a second

  nanosleep(&t, NULL);
}

///////////////////////////// Middle layer //////////////////////////////////////

// Read the input from the keyboard or a pipe
int _twopence_read_input
  (ssh_channel channel, bool *nothing, bool *eof)
{
  char buffer[BUFFER_SIZE];
  int size, written;

  // Read from stdin
  size = read(0, buffer, BUFFER_SIZE);
  if (size < 0)
  {
    if (errno != EAGAIN)               // Error
      return -1;
    *nothing = true;                   // Nothing to read
    return 0;
  }
  if (size == 0)                       // End of file
  {
    *nothing = true;
    *eof = true;
    if (ssh_channel_send_eof(channel) == SSH_ERROR)
      return -1;
    return 0;
  }
  written = ssh_channel_write          // Data, forward it to the remote host
    (channel, buffer, size);
  if (written != size)
    return -1;
  *nothing = false;
  return 0;
}

// Read the output of the system under test
//   'fd': 1 for stdout, 2 for stderr
//
// Returns 0 if everything went fine, a negative error code otherwise
int _twopence_read_output
  (struct twopence_ssh_target *handle, ssh_channel channel, bool error, bool *nothing, bool *eof)
{
  char buffer[BUFFER_SIZE];
  int size;

  size = ssh_channel_read_nonblocking
           (channel, buffer, BUFFER_SIZE, error? 1: 0);
  switch (size)
  {
    case SSH_ERROR:
      return -1;
    case SSH_EOF:
      *nothing = true;
      *eof = true;
      break;
    case 0:
      *nothing = true;
      break;
    default:
      if (_twopence_process_chunk
            (handle, buffer, size, error) < 0) return -2;
      *nothing = false;
  }
  return 0;
}

// Read the results of a command
int _twopence_read_results
  (struct twopence_ssh_target *handle, ssh_channel channel)
{
  bool nothing_0, eof_0,
       nothing_1, eof_1,
       nothing_2, eof_2;
  time_t too_late;

  eof_0 = eof_1 = eof_2 = false;
  too_late = time(NULL) + LONG_TIMEOUT;

  // While there might still be something to read from the remote host
  while (!eof_1 || !eof_2)
  {
    // Nonblocking read from stdin
    if (!eof_0)
    {
      if (_twopence_read_input(channel, &nothing_0, &eof_0) < 0)
        return -1;
    }

    // Nonblocking read from stdout
    if (!eof_1)
    {
      if (_twopence_read_output(handle, channel, false, &nothing_1, &eof_1) < 0)
        return -2;
    }

    // Nonblocking read from stderr
    if (!eof_2)
    {
      if (_twopence_read_output(handle, channel, true, &nothing_2, &eof_2) < 0)
        return -3;
    }

    // If we had nothing to read
    if (nothing_0 && nothing_1 && nothing_2)
    {
      // Then avoid active wait
      _twopence_sleep();

      // And check for timeout
      if (time(NULL) > too_late)
        return -4;
    }
    else too_late = time(NULL) + LONG_TIMEOUT;
  }
  return 0;
}

// Send a file in chunks through SCP
//
// Returns 0 if everything went fine, or a negative error code if failed
int _twopence_send_file
  (struct twopence_ssh_target *handle, int file_fd, ssh_scp scp, int remaining, int *remote_rc)
{
  char buffer[BUFFER_SIZE];
  int size, received;

  while (remaining > 0)
  {
    size = remaining < BUFFER_SIZE?    // Read at most BUFFER_SIZE bytes from the file
           remaining:
           BUFFER_SIZE;
    received = read(file_fd, buffer, size);
    if (received != size)
    {
      _twopence_output(handle, '\n');
      return TWOPENCE_LOCAL_FILE_ERROR;
    }

    if (ssh_scp_write
          (scp, buffer, size) != SSH_OK)
    {
      *remote_rc = ssh_get_error_code(handle->session);
      _twopence_output(handle, '\n');
      return TWOPENCE_SEND_FILE_ERROR;
    }

    _twopence_output(handle, '.');     // Progression dots
    remaining -= size;                 // That much we don't need to send anymore
  }
  _twopence_output(handle, '\n');
  return 0;
}

// Receive a file in chunks through SCP
//
// Returns 0 if everything went fine, or a negative error code if failed
int _twopence_receive_file
  (struct twopence_ssh_target *handle, int file_fd, ssh_scp scp, int remaining, int *remote_rc)
{
  char buffer[BUFFER_SIZE];
  int size, received, written;

  while (remaining > 0)
  {
    size = remaining > BUFFER_SIZE?    // Read at most BUFFER_SIZE bytes from the remote host
           BUFFER_SIZE:
           remaining;
    received = ssh_scp_read(scp, buffer, size);
    if (received != size)
    {
      *remote_rc = ssh_get_error_code(handle->session);
      _twopence_output(handle, '\n');
      return TWOPENCE_RECEIVE_FILE_ERROR;
    }

    written = write                    // Write these data locally
      (file_fd, buffer, size);
    if (written != size)
    {
      _twopence_output(handle, '\n');
      return TWOPENCE_LOCAL_FILE_ERROR;
    }

    _twopence_output(handle, '.');     // Progression dots
    remaining -= size;                 // That's that much less to receive
  }
  _twopence_output(handle, '\n');
  return 0;
}

///////////////////////////// Top layer /////////////////////////////////////////

// Open a SSH session as some user
//
// Returns 0 if everything went fine, a negative error code otherwise
int _twopence_connect_ssh
  (struct twopence_ssh_target *handle, const char *username)
{
  ssh_session session;

  // Create a new session based on the session template
  session = ssh_new();                 // FIXME: according to the documentation, we should not allocate 'session' ourselves (?)
  if (session == NULL)
    return -1;
  if (ssh_options_copy(handle->template, &session) < 0)
  {
    ssh_free(session);
    return -2;
  }

  // Store the username
  if (ssh_options_set(session, SSH_OPTIONS_USER, username) < 0)
  {
    ssh_free(session);
    return -3;
  }

  // Connect to the server
  if (ssh_connect(session) != SSH_OK)
  {
    ssh_free(session);
    return -4;
  }

  // Authenticate with our private key, with no passphrase
  // That's the only available method, given that we are in the context of testing
  // For safety reasons, do not use such private keys with no passphrases to access production systems
  if (ssh_userauth_autopubkey(session, NULL) != SSH_AUTH_SUCCESS)
  {
    ssh_disconnect(session);
    ssh_free(session);
    return -5;
  }

  // Write down the session
  // From now on, the caller is responsible to cleanup with ssh_disconnect() and ssh_free()
  handle->session = session;
  return 0;
}

// Submit a command to the remote host
//
// Returns 0 if everything went fine, a negative error code otherwise
int _twopence_command_ssh
  (struct twopence_ssh_target *handle, const char *command, int *minor)
{
  ssh_session session = handle->session;
  ssh_channel channel;
  int rc;

  // Tune stdin so it is nonblocking
  if (_twopence_tune_stdin(false) < 0)
  {
    return TWOPENCE_OPEN_SESSION_ERROR;
  }

  // We need a SSH channel to get the results
  channel = ssh_channel_new(session);
  if (channel == NULL)
  {
    _twopence_tune_stdin(true);
    return TWOPENCE_OPEN_SESSION_ERROR;
  }
  if (ssh_channel_open_session(channel) != SSH_OK)
  {
    ssh_channel_free(channel);
    _twopence_tune_stdin(true);
    return TWOPENCE_OPEN_SESSION_ERROR;
  }
  handle->channel = channel;

  // Execute the command
  if (ssh_channel_request_exec(channel, command) != SSH_OK)
  {
    handle->channel = NULL;
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    _twopence_tune_stdin(true);
    return TWOPENCE_SEND_COMMAND_ERROR;
  }
  handle->channel = NULL;

  // Read "standard output", "standard error", and remote error code
  rc = _twopence_read_results
    (handle, channel);

  // Get remote error code and terminate the channel
  ssh_channel_send_eof(channel);
  ssh_channel_close(channel);
  *minor = ssh_channel_get_exit_status(channel);
  ssh_channel_free(channel);
  _twopence_tune_stdin(true);
  return rc;
}

// Inject a file into the remote host through SSH
//
// Returns 0 if everything went fine
int _twopence_inject_ssh
  (struct twopence_ssh_target *handle, int file_fd, const char *remote_filename, int *remote_rc)
{
  ssh_session session = handle->session;
  char *copy;
  ssh_scp scp;
  struct stat filestats;
  int rc;

  // Create and initialize a SCP session
  copy = strdup(remote_filename);
  scp = ssh_scp_new(session, SSH_SCP_WRITE, dirname(copy));
  free(copy);
  if (scp == NULL)
    return TWOPENCE_OPEN_SESSION_ERROR;
  if (ssh_scp_init(scp) != SSH_OK)
  {
    ssh_scp_free(scp);
    return TWOPENCE_OPEN_SESSION_ERROR;
  }

  // Tell the remote host about the file size
  fstat(file_fd, &filestats);
  copy = strdup(remote_filename);
  if (ssh_scp_push_file
         (scp, basename(copy), filestats.st_size, 00660) != SSH_OK)
  {
    *remote_rc = ssh_get_error_code(session);
    free(copy);
    ssh_scp_close(scp);
    ssh_scp_free(scp);
    return TWOPENCE_SEND_FILE_ERROR;
  }
  free(copy);

  // Send the file
  rc = _twopence_send_file
        (handle, file_fd, scp, filestats.st_size, remote_rc);

  // Close the SCP session
  ssh_scp_close(scp);
  ssh_scp_free(scp);
  return rc;
}

// Extract a file from the remote host through SSH
//
// Returns 0 if everything went fine
int _twopence_extract_ssh
      (struct twopence_ssh_target *handle, int file_fd, const char *remote_filename, int *remote_rc)
{
  ssh_session session = handle->session;
  ssh_scp scp;
  int size, rc;

  // Create and initialize a SCP session
  scp = ssh_scp_new(session, SSH_SCP_READ, remote_filename);
  if (scp == NULL)
    return TWOPENCE_OPEN_SESSION_ERROR;
  if (ssh_scp_init(scp) != SSH_OK)
  {
    ssh_scp_free(scp);
    return TWOPENCE_OPEN_SESSION_ERROR;
  }

  // Get the file size from the remote host
  if (ssh_scp_pull_request(scp) != SSH_SCP_REQUEST_NEWFILE)
  {
    *remote_rc = ssh_get_error_code(session);
    ssh_scp_close(scp);
    ssh_scp_free(scp);
    return TWOPENCE_RECEIVE_FILE_ERROR;
  }
  size = ssh_scp_request_get_size(scp);

  // Accept the transfer request
  if (ssh_scp_accept_request(scp) != SSH_OK)
  {
    *remote_rc = ssh_get_error_code(session);
    ssh_scp_close(scp);
    ssh_scp_free(scp);
    return TWOPENCE_RECEIVE_FILE_ERROR;
  }

  // Receive the file
  rc = _twopence_receive_file
        (handle, file_fd, scp, size, remote_rc);
  if (rc < 0)
  {
    ssh_scp_close(scp);
    ssh_scp_free(scp);
    return rc;
  }

  // Check for proper termination
  if (ssh_scp_pull_request(scp) != SSH_SCP_REQUEST_EOF)
  {
    *remote_rc = ssh_get_error_code(session);
    ssh_scp_close(scp);
    ssh_scp_free(scp);
    return TWOPENCE_RECEIVE_FILE_ERROR;
  }

  // Close the SCP session
  ssh_scp_close(scp);
  ssh_scp_free(scp);
  return 0;
}

// Disconnect from the remote host
void _twopence_disconnect_ssh
  (struct twopence_ssh_target *handle)
{
  ssh_session session = handle->session;

  ssh_disconnect(session);
  ssh_free(session);

  handle->session = NULL;
}

// Interrupt current command
//
// Returns 0 if everything went fine, or a negative error code if failed
int _twopence_interrupt_ssh
  (struct twopence_ssh_target *handle)
{
  ssh_channel channel = handle->channel;

  if (channel == NULL) return TWOPENCE_OPEN_SESSION_ERROR;

  // This is currently completly useless with OpenSSH
  // (see https://bugzilla.mindrot.org/show_bug.cgi?id=1424)
  if (ssh_channel_request_send_signal(channel, "INT") != SSH_OK)
    return TWOPENCE_INTERRUPT_COMMAND_ERROR;

  return 0;
}

///////////////////////////// Public interface //////////////////////////////////

// Initialize the library
//
// This specific plugin takes an IP address or an hostname as argument
//
// Returns a "handle" that must be passed to subsequent function calls,
// or NULL in case of a problem
struct twopence_target *twopence_init
  (const char *hostname, unsigned int port)
{
  struct twopence_ssh_target *handle;
  ssh_session template;

  // Allocate the opaque handle
  handle = malloc(sizeof(struct twopence_ssh_target));
  if (handle == NULL) return NULL;

  // Store the plugin type
  handle->type = 1;                    // ssh

  // Create the SSH session template
  template = ssh_new();
  if (template == NULL)
  {
    free(handle);
    return NULL;
  }

  // Store the hostname and the port number
  if (ssh_options_set(template, SSH_OPTIONS_HOST, hostname) < 0 ||
      ssh_options_set(template, SSH_OPTIONS_PORT, &port) < 0
     )
  {
    ssh_free(template);
    free(handle);
    return NULL;
  }

  // Register the SSH session template and return the handle
  handle->template = template;
  handle->session = NULL;
  handle->channel = NULL;
  return (struct twopence_target *) handle;
};

// Run a test command, and print output
//
// Returns 0 if everything went fine
// 'major' is the return code of the test server (none for SSH)
// 'minor' is the return code of the command
int twopence_test_and_print_results
  (struct twopence_target *opaque_handle, const char *username, const char *command,
   int *major, int *minor)
{
  struct twopence_ssh_target *handle = (struct twopence_ssh_target *) opaque_handle;
  int rc;

  // 'major' makes no sense for SSH and 'minor' defaults to 0
  *major = *minor = 0;

  // Output will happen on the screen
  handle->output_mode = to_screen;

  // Connect to the remote host
  if (_twopence_connect_ssh(handle, username) < 0)
    return TWOPENCE_OPEN_SESSION_ERROR;

  // Execute the command
  rc = _twopence_command_ssh(handle, command, minor);

  // Disconnect from remote host
  _twopence_disconnect_ssh(handle);
  return rc;
}

// Run a test command, and drop output
//
// Returns 0 if everything went fine
// 'major' is the return code of the test server (none for SSH)
// 'minor' is the return code of the command
int twopence_test_and_drop_results
  (struct twopence_target *opaque_handle, const char *username, const char *command,
   int *major, int *minor)
{
  struct twopence_ssh_target *handle = (struct twopence_ssh_target *) opaque_handle;
  int rc;

  // 'major' makes no sense for SSH and 'minor' defaults to 0
  *major = *minor = 0;

  // Output will happen on the screen
  handle->output_mode = no_output;

  // Connect to the remote host
  if (_twopence_connect_ssh(handle, username) < 0)
    return TWOPENCE_OPEN_SESSION_ERROR;

  // Execute the command
  rc = _twopence_command_ssh(handle, command, minor);

  // Disconnect from remote host
  _twopence_disconnect_ssh(handle);
  return rc;
}

// Run a test command, and store the results in memory in a common buffer
//
// Returns 0 if everything went fine
// 'major' is the return code of the test server (none for SSH)
// 'minor' is the return code of the command
int twopence_test_and_store_results_together
  (struct twopence_target *opaque_handle, const char *username, const char *command,
   char *buffer_out, int size,
   int *major, int *minor)
{
  struct twopence_ssh_target *handle = (struct twopence_ssh_target *) opaque_handle;
  int rc;

  // 'major' makes no sense for SSH and 'minor' defaults to 0
  *major = *minor = 0;

  // Output will happen in the common buffer
  handle->output_mode = common_buffer;
  handle->buffer_out = buffer_out; handle->end_out = buffer_out + size;

  // Connect to the remote host
  if (_twopence_connect_ssh(handle, username) < 0)
    return TWOPENCE_OPEN_SESSION_ERROR;

  // Execute the command
  rc = _twopence_command_ssh(handle, command, minor);

  // Disconnect from remote host
  _twopence_disconnect_ssh(handle);

  // Store final NUL
  if (rc == 0)
  {
    if (_twopence_output(handle, '\0') < 0)
      rc = TWOPENCE_RECEIVE_RESULTS_ERROR;
  }
  return rc;
}

// Run a test command, and store the results in memory in two separate buffers
//
// Returns 0 if everything went fine
// 'major' is the return code of the test server (none for SSH)
// 'minor' is the return code of the command
int twopence_test_and_store_results_separately
  (struct twopence_target *opaque_handle, const char *username, const char *command,
   char *buffer_out, char *buffer_err, int size,
   int *major, int *minor)
{
  struct twopence_ssh_target *handle = (struct twopence_ssh_target *) opaque_handle;
  int rc;

  // 'major' makes no sense for SSH and 'minor' defaults to 0
  *major = *minor = 0;

  // Output will happen in the separate buffers
  handle->output_mode = separate_buffers;
  handle->buffer_out = buffer_out; handle->end_out = buffer_out + size;
  handle->buffer_err = buffer_err; handle->end_err = buffer_err + size;

  // Connect to the remote host
  if (_twopence_connect_ssh(handle, username) < 0)
    return TWOPENCE_OPEN_SESSION_ERROR;

  // Execute the command
  rc = _twopence_command_ssh(handle, command, minor);

  // Disconnect from remote host
  _twopence_disconnect_ssh(handle);

  // Store final NULs
  if (rc == 0)
  {
    if (_twopence_output(handle, '\0') < 0)
      rc = TWOPENCE_RECEIVE_RESULTS_ERROR;
  }
  if (rc == 0)
  {
    if (_twopence_error(handle, '\0') < 0)
      rc = TWOPENCE_RECEIVE_RESULTS_ERROR;
  }
  return rc;
}

// Inject a file into the remote host
//
// Returns 0 if everything went fine
int twopence_inject_file
  (struct twopence_target *opaque_handle, const char *username,
   const char *local_filename, const char *remote_filename,
   int *remote_rc, bool dots)
{
  struct twopence_ssh_target *handle = (struct twopence_ssh_target *) opaque_handle;
  int fd, rc;

  // 'remote_rc' defaults to 0
  *remote_rc = 0;

  handle->output_mode = dots? to_screen: no_output;

  // Open the file
  fd = open(local_filename, O_RDONLY);
  if (fd == -1)
    return errno == ENAMETOOLONG?
           TWOPENCE_PARAMETER_ERROR:
           TWOPENCE_LOCAL_FILE_ERROR;

  // Connect to the remote host
  if (_twopence_connect_ssh(handle, username) < 0)
  {
    close(fd);
    return TWOPENCE_OPEN_SESSION_ERROR;
  }

  // Inject the file
  rc = _twopence_inject_ssh
         (handle, fd, remote_filename, remote_rc);
  if (rc == 0 && *remote_rc != 0)
    rc = TWOPENCE_REMOTE_FILE_ERROR;

  // Disconnect from remote host
  _twopence_disconnect_ssh(handle);

  // Close the file
  close(fd);

  return rc;
}

// Extract a file from the remote host
//
// Returns 0 if everything went fine
int twopence_extract_file
  (struct twopence_target *opaque_handle, const char *username,
   const char *remote_filename, const char *local_filename,
   int *remote_rc, bool dots)
{
  struct twopence_ssh_target *handle = (struct twopence_ssh_target *) opaque_handle;
  int fd, rc;

  // 'remote_rc' defaults to 0
  *remote_rc = 0;

  handle->output_mode = dots? to_screen: no_output;

  // Open the file, creating it if it does not exist (u=rw,g=rw,o=)
  fd = creat(local_filename, 00660);
  if (fd == -1)
    return errno == ENAMETOOLONG?
           TWOPENCE_PARAMETER_ERROR:
           TWOPENCE_LOCAL_FILE_ERROR;

  // Connect to the remote host
  if (_twopence_connect_ssh(handle, username) < 0)
  {
    close(fd);
    return TWOPENCE_OPEN_SESSION_ERROR;
  }

  // Extract the file
  rc = _twopence_extract_ssh
         (handle, fd, remote_filename, remote_rc);
  if (rc == 0 && *remote_rc != 0)
    rc = TWOPENCE_REMOTE_FILE_ERROR;

  // Disconnect from remote host
  _twopence_disconnect_ssh(handle);

  // Close the file
  close(fd);

  return rc;
}

// Interrupt current command
//
// Returns 0 if everything went fine
int twopence_interrupt_command(struct twopence_target *opaque_handle)
{
  struct twopence_ssh_target *handle = (struct twopence_ssh_target *) opaque_handle;

  return _twopence_interrupt_ssh(handle);
}

// Tell the remote test server to exit
//
// Returns 0 if everything went fine
int twopence_exit_remote(struct twopence_target *opaque_handle)
{
  return -1;                           // Makes no sense with SSH
}

// Close the library
void twopence_end(struct twopence_target *opaque_handle)
{
  struct twopence_ssh_target *handle = (struct twopence_ssh_target *) opaque_handle;

  ssh_free(handle->template);
  free(handle);
}
