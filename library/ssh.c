/*
Test executor, ssh plugin.
It is used to send tests to real machines or VMs using SSH protocol.


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

#include <libssh/libssh.h>

#include <sys/stat.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <libgen.h>

#include <string.h>
#include <stdlib.h>
#include <malloc.h>
#include <signal.h>
#include <assert.h>

#include "twopence.h"

#define BUFFER_SIZE 16384              // Size in bytes of the work buffer for receiving data from the remote host
#define LINE_TIMEOUT 60                // Timeout (in seconds) for not receiving anything

// This structure encapsulates in an opaque way the behaviour of the library
// It is not 100 % opaque, because it is publicly known that the first field is the plugin type
struct twopence_ssh_target
{
  struct twopence_target base;

  ssh_session template, session;
  ssh_channel channel;                 // Set during remote command execution only
  bool use_tty;
  bool eof_sent;
  bool interrupted;
};

extern const struct twopence_plugin twopence_ssh_ops;

///////////////////////////// Lower layer ///////////////////////////////////////

// Output a "stdout" character through one of the available methods
//
// Returns 0 if everything went fine, a negative error code otherwise
static inline int
__twopence_ssh_output(struct twopence_ssh_target *handle, char c)
{
  return twopence_target_putc(&handle->base, TWOPENCE_STDOUT, c);
}

// Output a "stderr" character through one of the available methods
//
// Returns 0 if everything went fine, a negative error code otherwise
static inline int
__twopence_ssh_error(struct twopence_ssh_target *handle, char c)
{
  return twopence_target_putc(&handle->base, TWOPENCE_STDERR, c);
}

// Process chunk of data sent by the remote host
//
// Returns 0 if everything went fine, a negative error code otherwise
static int
__twopence_ssh_process_chunk(struct twopence_ssh_target *handle, const char *buffer, int size, bool error)
{
  twopence_iofd_t dst = error? TWOPENCE_STDERR : TWOPENCE_STDOUT;
  int written;

  written = twopence_target_write(&handle->base, dst, buffer, size);
  return written < 0? written : 0;
}

// Avoid active wait by sleeping
static void
__twopence_ssh_sleep()
{
  struct timespec t;

  t.tv_sec = 0;
  t.tv_nsec = 20000000L;               // 1/50th of a second

  nanosleep(&t, NULL);
}

static int
__twopence_ssh_channel_eof(struct twopence_ssh_target *handle)
{
  int rc = SSH_OK;

  if (handle->channel == NULL || handle->eof_sent)
    return SSH_OK;
  if (handle->use_tty)
    rc = ssh_channel_write(handle->channel, "\004", 1);
  if (rc == SSH_OK)
    rc = ssh_channel_send_eof(handle->channel);
  if (rc == SSH_OK)
    handle->eof_sent = true;
  return rc;
}

static void
__twopence_ssh_close_channel(struct twopence_ssh_target *handle)
{
  if (handle->channel == NULL)
    return;

  ssh_channel_close(handle->channel);
  ssh_channel_free(handle->channel);
  handle->channel = NULL;
}

///////////////////////////// Middle layer //////////////////////////////////////

// Read the input from the keyboard or a pipe
static int
__twopence_ssh_read_input(struct twopence_ssh_target *handle, ssh_channel channel, bool *nothing, bool *eof)
{
  twopence_iostream_t *stream;
  char buffer[BUFFER_SIZE];
  int size, written;

  stream = twopence_target_stream(&handle->base, TWOPENCE_STDIN);
  if (stream == NULL || twopence_iostream_eof(stream)) {
    *nothing = *eof = true;
    return 0;
  }

  // Read from stdin
  size = twopence_iostream_read(stream, buffer, BUFFER_SIZE);
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
    if (__twopence_ssh_channel_eof(handle) == SSH_ERROR)
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
static int
__twopence_ssh_read_output(struct twopence_ssh_target *handle, ssh_channel channel, bool error, bool *nothing, bool *eof)
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
      if (__twopence_ssh_process_chunk(handle, buffer, size, error) < 0)
	      return -2;
      *nothing = false;
  }
  return 0;
}

// Read the results of a command
static int
__twopence_ssh_read_results(struct twopence_ssh_target *handle, long timeout, ssh_channel channel)
{
  bool nothing_0, eof_0,
       nothing_1, eof_1,
       nothing_2, eof_2;
  time_t line_too_late,
         command_too_late;

  eof_0 = eof_1 = eof_2 = false;
  line_too_late = command_too_late = time(NULL);
  line_too_late += LINE_TIMEOUT;
  command_too_late += timeout;

  // While there might still be something to read from the remote host
  while (!eof_1 || !eof_2)
  {
    // If we have received a SIGINT, exit and close the channel without
    // further delay.
    if (handle->interrupted) {
      printf("interrupt: break out of read loop\n");
      return -6;
    }

    // Nonblocking read from stdin
    if (!eof_0)
    {
      if (__twopence_ssh_read_input(handle, channel, &nothing_0, &eof_0) < 0)
        return -1;
    }

    // Nonblocking read from stdout
    if (!eof_1)
    {
      if (__twopence_ssh_read_output(handle, channel, false, &nothing_1, &eof_1) < 0)
        return -2;
    }

    // Nonblocking read from stderr
    if (!eof_2)
    {
      if (__twopence_ssh_read_output(handle, channel, true, &nothing_2, &eof_2) < 0)
        return -3;
    }

    /* The following looks wrong to me. There has to be some select based
     * mechanism to handle this sort of sleep/poll cycle. --okir 
     *
     * Yes. There is ssh_select(), see
     *   http://api.libssh.org/stable/group__libssh__channel.html.
     * For the TODO. --ebischoff
     */

    // If we had nothing to read
    if (nothing_0 && nothing_1 && nothing_2)
    {
      // Then avoid active wait
      __twopence_ssh_sleep();

      // And check for timeout
      if (time(NULL) > line_too_late)
        return -4;

    if (time(NULL) > command_too_late)
     return -5;
    }
    else line_too_late = time(NULL) + LINE_TIMEOUT;
  }
  return 0;
}

// Send a file in chunks through SCP
//
// Returns 0 if everything went fine, or a negative error code if failed
static int
__twopence_ssh_send_file(struct twopence_ssh_target *handle, twopence_iostream_t *local_stream, ssh_scp scp, int remaining, int *remote_rc)
{
  char buffer[BUFFER_SIZE];
  int size, received;

  while (remaining > 0)
  {
    size = remaining < BUFFER_SIZE?    // Read at most BUFFER_SIZE bytes from the file
           remaining:
           BUFFER_SIZE;
    received = twopence_iostream_read(local_stream, buffer, size);
    if (received != size)
    {
      __twopence_ssh_output(handle, '\n');
      return TWOPENCE_LOCAL_FILE_ERROR;
    }

    if (ssh_scp_write
          (scp, buffer, size) != SSH_OK)
    {
      *remote_rc = ssh_get_error_code(handle->session);
      __twopence_ssh_output(handle, '\n');
      return TWOPENCE_SEND_FILE_ERROR;
    }

    __twopence_ssh_output(handle, '.');     // Progression dots
    remaining -= size;                 // That much we don't need to send anymore
  }
  __twopence_ssh_output(handle, '\n');
  return 0;
}

// Receive a file in chunks through SCP
//
// Returns 0 if everything went fine, or a negative error code if failed
static int
__twopence_ssh_receive_file(struct twopence_ssh_target *handle, twopence_iostream_t *local_stream, ssh_scp scp, int remaining, int *remote_rc)
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
      __twopence_ssh_output(handle, '\n');
      return TWOPENCE_RECEIVE_FILE_ERROR;
    }

    written = twopence_iostream_write(local_stream, buffer, size);
    if (written != size)
    {
      __twopence_ssh_output(handle, '\n');
      return TWOPENCE_LOCAL_FILE_ERROR;
    }

    __twopence_ssh_output(handle, '.');     // Progression dots
    remaining -= size;                 // That's that much less to receive
  }
  __twopence_ssh_output(handle, '\n');
  return 0;
}

///////////////////////////// Top layer /////////////////////////////////////////

// Open a SSH session as some user
//
// Returns 0 if everything went fine, a negative error code otherwise
static int
__twopence_ssh_connect_ssh(struct twopence_ssh_target *handle, const char *username)
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
static int
__twopence_ssh_command_ssh
    (struct twopence_ssh_target *handle, twopence_command_t *cmd, twopence_status_t *status_ret)
{
  ssh_session session = handle->session;
  ssh_channel channel;
  int was_blocking;
  int rc;

  // Tune stdin so it is nonblocking
  was_blocking = twopence_target_set_blocking(&handle->base, TWOPENCE_STDIN, false);
  if (was_blocking < 0)
    return TWOPENCE_OPEN_SESSION_ERROR;

  // We need a SSH channel to get the results
  channel = ssh_channel_new(session);
  if (channel == NULL)
  {
    twopence_target_set_blocking(&handle->base, TWOPENCE_STDIN, was_blocking);
    return TWOPENCE_OPEN_SESSION_ERROR;
  }
  if (ssh_channel_open_session(channel) != SSH_OK)
  {
    ssh_channel_free(channel);
    twopence_target_set_blocking(&handle->base, TWOPENCE_STDIN, was_blocking);
    return TWOPENCE_OPEN_SESSION_ERROR;
  }
  handle->channel = channel;
  handle->eof_sent = false;
  handle->use_tty = false;
  handle->interrupted = false;

  // Request that the command be run inside a tty
  if (cmd->request_tty)
  {
    if (ssh_channel_request_pty(channel) != SSH_OK)
    {
      __twopence_ssh_close_channel(handle);
      twopence_target_set_blocking(&handle->base, TWOPENCE_STDIN, was_blocking);
      return TWOPENCE_OPEN_SESSION_ERROR;
    }
    handle->use_tty = true;
  }

  // Execute the command
  if (ssh_channel_request_exec(channel, cmd->command) != SSH_OK)
  {
    __twopence_ssh_close_channel(handle);
    twopence_target_set_blocking(&handle->base, TWOPENCE_STDIN, was_blocking);
    return TWOPENCE_SEND_COMMAND_ERROR;
  }

  // Read "standard output", "standard error", and remote error code
  rc = __twopence_ssh_read_results(handle, cmd->timeout, channel);

  /* FIXME: might be better to return useful status values from
   * __twopence_ssh_read_results in the first place. Currently we
   * don't, thus we need to translate them here.
   */
  status_ret->minor = 0;
  switch (rc)
  {
    case 0:
      status_ret->minor = ssh_channel_get_exit_status(channel);
      break;

    case -1:
      rc = TWOPENCE_FORWARD_INPUT_ERROR;
      break;

    case -2:
    case -3:
    case -4:
      rc = TWOPENCE_RECEIVE_RESULTS_ERROR;
      break;

    case -5:
      rc = TWOPENCE_COMMAND_TIMEOUT_ERROR;
      break;

    case -6:
      /* The following matches what the serial/virtio server code currently
       * does, but it feels wrong. What about TWOPENCE_COMMAND_INTERRUPTED_ERROR?
       */
      status_ret->major = EFAULT;
      status_ret->minor = SIGINT;
      rc = 0;
      break;

    default:
      rc = TWOPENCE_RECEIVE_RESULTS_ERROR;
  }

  // Terminate the channel
  __twopence_ssh_channel_eof(handle);
  __twopence_ssh_close_channel(handle);

  twopence_target_set_blocking(&handle->base, TWOPENCE_STDIN, was_blocking);
  return rc;
}

static bool
__twopence_ssh_check_remote_dir(struct twopence_ssh_target *handle, const char *remote_dirname)
{
  ssh_session session = handle->session;
  ssh_scp scp = NULL;
  bool exists = false;

  scp = ssh_scp_new(session, SSH_SCP_READ|SSH_SCP_RECURSIVE, remote_dirname);
  if (scp != NULL
   && ssh_scp_init(scp) == SSH_OK
   && ssh_scp_pull_request(scp) == SSH_SCP_REQUEST_NEWDIR)
    exists = true;

  if (scp) {
    ssh_scp_close(scp);
    ssh_scp_free(scp);
  }

  return exists;
}

// Inject a file into the remote host through SSH
//
// Returns 0 if everything went fine
static int
__twopence_ssh_inject_ssh(struct twopence_ssh_target *handle, twopence_file_xfer_t *xfer,
		const char *remote_dirname, const char *remote_basename,
		twopence_status_t *status)
{
  ssh_session session = handle->session;
  ssh_scp scp;
  long filesize;
  int rc;

  filesize = twopence_iostream_filesize(xfer->local_stream);
  assert(filesize >= 0);

  /* Unfortunately, we have to make sure the remote directory exists.
   * In openssh-6.2p2 (and maybe others), if you try to create file
   * "foo" inside non-existant directory "/bar" will result in the
   * creation of regular file "/bar" and upload the content there.
   */
  if (!__twopence_ssh_check_remote_dir(handle, remote_dirname))
    return TWOPENCE_SEND_FILE_ERROR;

  scp = ssh_scp_new(session, SSH_SCP_WRITE, remote_dirname);
  if (scp == NULL)
    return TWOPENCE_OPEN_SESSION_ERROR;
  if (ssh_scp_init(scp) != SSH_OK)
  {
    ssh_scp_free(scp);
    return TWOPENCE_OPEN_SESSION_ERROR;
  }

  // Tell the remote host about the file size
  if (ssh_scp_push_file
         (scp, remote_basename, filesize, xfer->remote.mode) != SSH_OK)
  {
    status->major = ssh_get_error_code(session);
    ssh_scp_close(scp);
    ssh_scp_free(scp);
    return TWOPENCE_SEND_FILE_ERROR;
  }

  // Send the file
  rc = __twopence_ssh_send_file(handle, xfer->local_stream, scp, filesize, &status->major);

  // Close the SCP session
  ssh_scp_close(scp);
  ssh_scp_free(scp);
  return rc;
}

// Extract a file from the remote host through SSH
//
// Returns 0 if everything went fine
static int
__twopence_ssh_extract_ssh(struct twopence_ssh_target *handle, twopence_iostream_t *local_stream, const char *remote_filename, int *remote_rc)
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
  if (!size) return 0;

  // Accept the transfer request
  if (ssh_scp_accept_request(scp) != SSH_OK)
  {
    *remote_rc = ssh_get_error_code(session);
    ssh_scp_close(scp);
    ssh_scp_free(scp);
    return TWOPENCE_RECEIVE_FILE_ERROR;
  }

  // Receive the file
  rc = __twopence_ssh_receive_file
        (handle, local_stream, scp, size, remote_rc);
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
void
__twopence_ssh_disconnect_ssh(struct twopence_ssh_target *handle)
{
  ssh_session session = handle->session;

  ssh_disconnect(session);
  ssh_free(session);

  handle->session = NULL;
}

// Interrupt current command
//
// Returns 0 if everything went fine, or a negative error code if failed
static int
__twopence_ssh_interrupt_ssh(struct twopence_ssh_target *handle)
{
  ssh_channel channel = handle->channel;

  if (channel == NULL)
    return TWOPENCE_OPEN_SESSION_ERROR;

#if 0
  // This is currently completly useless with OpenSSH
  // (see https://bugzilla.mindrot.org/show_bug.cgi?id=1424)
  if (ssh_channel_request_send_signal(channel, "INT") != SSH_OK)
    return TWOPENCE_INTERRUPT_COMMAND_ERROR;
#else
  if (handle->use_tty) {
    if (handle->eof_sent) {
      printf("Cannot send Ctrl-C, channel already closed for writing\n");
      return TWOPENCE_INTERRUPT_COMMAND_ERROR;
    }

    if (ssh_channel_write(channel, "\003", 1) != 1)
      return TWOPENCE_INTERRUPT_COMMAND_ERROR;
  } else {
    printf("Command not being run in tty, cannot interrupt it\n");
    handle->interrupted = true;
  }
#endif

  return 0;
}

///////////////////////////// Public interface //////////////////////////////////

// Initialize the library
//
// This specific plugin takes an IP address or an hostname as argument
//
// Returns a "handle" that must be passed to subsequent function calls,
// or NULL in case of a problem
static struct twopence_target *
__twopence_ssh_init(const char *hostname, unsigned int port)
{
  struct twopence_ssh_target *handle;
  ssh_session template;

  // Allocate the opaque handle
  handle = calloc(1, sizeof(struct twopence_ssh_target));
  if (handle == NULL) return NULL;

  // Store the plugin type
  handle->base.plugin_type = TWOPENCE_PLUGIN_SSH;
  handle->base.ops = &twopence_ssh_ops;

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

//////////////////////////////////////////////////////////////////
// This is the new way of initializing the library.
// This function expects just the part of the target spec following
// the "ssh:" plugin type.
//////////////////////////////////////////////////////////////////
struct twopence_target *
twopence_init_new(const char *arg)
{
  char *copy_spec, *s, *hostname;
  struct twopence_target *target = NULL;
  unsigned long port;

  /* The arg can have a trailing ":<portnum>" portion. Split
   * that off. */
  if (strrchr(arg, ':') == NULL) {
    /* Just a hostname */
    return __twopence_ssh_init(arg, 22);
  }

  copy_spec = strdup(arg);
  s = strrchr(copy_spec, ':');
  *s++ = '\0';
 
  port = strtoul(s, &s, 10);
  if (*s != '\0' || port >= 65535) {
    /* FIXME: we should complain about an invalid port number.
     * Right now, we just fail silently - as we do with every
     * other invalid piece of input. 
     */
    free(copy_spec);
    return NULL;
  }

  /* The hostname portion may actually be an IPv6 like [::1].
   * Strip off the outer brackets */
  hostname = copy_spec;
  if (*hostname == '[') {
    int n = strlen(hostname);

    if (hostname[n-1] == ']') {
      hostname[n-1] = '\0';
      ++hostname;
    }
  }

  target = __twopence_ssh_init(hostname, port);

  free(copy_spec);
  return target;
}

/*
 * Run a test
 */
static int
twopence_ssh_run_test
  (struct twopence_target *opaque_handle, twopence_command_t *cmd, twopence_status_t *status_ret)
{
  struct twopence_ssh_target *handle = (struct twopence_ssh_target *) opaque_handle;
  int rc;

  if (cmd->command == NULL)
    return TWOPENCE_PARAMETER_ERROR;

  /* 'major' makes no sense for SSH and 'minor' defaults to 0 */
  memset(status_ret, 0, sizeof(*status_ret));

  handle->base.current.io = cmd->iostream;

  // Connect to the remote host
  if (__twopence_ssh_connect_ssh(handle, cmd->user?: "root") < 0)
    return TWOPENCE_OPEN_SESSION_ERROR;

  // Execute the command
  rc = __twopence_ssh_command_ssh(handle, cmd, status_ret);

  // Disconnect from remote host
  __twopence_ssh_disconnect_ssh(handle);

  return rc;
}


// Inject a file into the remote host
//
// Returns 0 if everything went fine
static int
twopence_ssh_inject_file(struct twopence_target *opaque_handle,
		twopence_file_xfer_t *xfer, twopence_status_t *status)
{
  struct twopence_ssh_target *handle = (struct twopence_ssh_target *) opaque_handle;
  char *dirname, *basename;
  long filesize;
  int rc;

  // Connect to the remote host
  if (__twopence_ssh_connect_ssh(handle, xfer->user) < 0)
    return TWOPENCE_OPEN_SESSION_ERROR;

  dirname = ssh_dirname(xfer->remote.name);
  basename = ssh_basename(xfer->remote.name);

  /* Unfortunately, the SCP protocol requires the size of the file to be
   * transmitted :-(
   *
   * If we've been asked to read from eg a pipe or some other special
   * iostream, just buffer everything and then send it as a whole.
   */
  filesize = twopence_iostream_filesize(xfer->local_stream);
  if (filesize < 0) {
    twopence_file_xfer_t tmp_xfer = *xfer;
    twopence_buf_t *bp;

    bp = twopence_iostream_read_all(xfer->local_stream);
    if (bp == NULL)
      return TWOPENCE_LOCAL_FILE_ERROR;

    tmp_xfer.local_stream = NULL;
    twopence_iostream_wrap_buffer(bp, &tmp_xfer.local_stream);
    rc = __twopence_ssh_inject_ssh(handle, &tmp_xfer, dirname, basename, status);
    twopence_iostream_free(tmp_xfer.local_stream);
  } else {
    rc = __twopence_ssh_inject_ssh(handle, xfer,dirname, basename,  status);
  }

  if (rc == 0 && (status->major != 0 || status->major != 0))
    rc = TWOPENCE_REMOTE_FILE_ERROR;

  // Disconnect from remote host
  __twopence_ssh_disconnect_ssh(handle);

  /* Clean up */
  free(basename);
  free(dirname);

  return rc;
}

// Extract a file from the remote host
//
// Returns 0 if everything went fine
static int
twopence_ssh_extract_file(struct twopence_target *opaque_handle,
		const char *username,
		const char *remote_filename, twopence_iostream_t *local_stream,
		int *remote_rc, bool dots)
{
  struct twopence_ssh_target *handle = (struct twopence_ssh_target *) opaque_handle;
  int rc;

  // 'remote_rc' defaults to 0
  *remote_rc = 0;

  // Connect to the remote host
  if (__twopence_ssh_connect_ssh(handle, username) < 0)
    return TWOPENCE_OPEN_SESSION_ERROR;

  // Extract the file
  rc = __twopence_ssh_extract_ssh
         (handle, local_stream, remote_filename, remote_rc);
  if (rc == 0 && *remote_rc != 0)
    rc = TWOPENCE_REMOTE_FILE_ERROR;

  // Disconnect from remote host
  __twopence_ssh_disconnect_ssh(handle);

  return rc;
}

// Interrupt current command
//
// Returns 0 if everything went fine
static int
twopence_ssh_interrupt_command(struct twopence_target *opaque_handle)
{
  struct twopence_ssh_target *handle = (struct twopence_ssh_target *) opaque_handle;

  return __twopence_ssh_interrupt_ssh(handle);
}

// Tell the remote test server to exit
//
// Returns 0 if everything went fine
static int
twopence_ssh_exit_remote(struct twopence_target *opaque_handle)
{
  return -1;                           // Makes no sense with SSH
}

// Close the library
static void
twopence_ssh_end(struct twopence_target *opaque_handle)
{
  struct twopence_ssh_target *handle = (struct twopence_ssh_target *) opaque_handle;

  ssh_free(handle->template);
  free(handle);
}

/*
 * Define the plugin ops vector
 */
const struct twopence_plugin twopence_ssh_ops = {
	.name		= "ssh",

	.init = twopence_init_new,
	.run_test = twopence_ssh_run_test,
	.inject_file = twopence_ssh_inject_file,
	.extract_file = twopence_ssh_extract_file,
	.exit_remote = twopence_ssh_exit_remote,
	.interrupt_command = twopence_ssh_interrupt_command,
	.end = twopence_ssh_end,
};
