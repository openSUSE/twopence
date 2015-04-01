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
#include <libssh/callbacks.h>

#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/time.h>
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
  int exit_signal;

  /* Right now, we need the callbacks for exactly one reason -
   * to catch the exit signal of the remote process.
   * When a command dies from a signal, libssh will always report
   * an exit code of -1 (SSH_ERROR), and the only way to catch what
   * really happens is by hooking up this callback.
   */
  struct ssh_channel_callbacks_struct callbacks;
};

// Read the results of a command
struct twopence_ssh_transaction {
	struct twopence_ssh_target *handle;
	ssh_channel		channel;

	struct {
	  twopence_iostream_t *	stream;;
	  struct pollfd		pfd;
	} stdin;

	bool			at_eof[3];

	struct timeval		command_timeout;
};

#if 0
# define SSH_TRACE(fmt...)	fprintf(stderr, fmt)
#else
# define SSH_TRACE(fmt...)	do { } while (0)
#endif

/* Note to self: if you need to find out what libssh is doing,
 * consider enabling tracing:
 *  ssh_set_log_level(SSH_LOG_TRACE);
 */

extern const struct twopence_plugin twopence_ssh_ops;
static int __twopence_ssh_interrupt_ssh(struct twopence_ssh_target *);

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

static struct twopence_ssh_transaction *
__twopence_ssh_transaction_new(struct twopence_ssh_target *handle, ssh_channel channel,
		twopence_iostream_t *stdin_stream, unsigned long timeout)
{
  struct twopence_ssh_transaction *trans;

  trans = calloc(1, sizeof(*trans));
  if (trans == NULL)
    return NULL;

  trans->handle = handle;
  trans->channel = channel;
  trans->stdin.stream = stdin_stream;
  trans->stdin.pfd.fd = -1;
  trans->stdin.pfd.revents = 0;

  gettimeofday(&trans->command_timeout, NULL);
  trans->command_timeout.tv_sec += timeout;

  return trans;
}

void
__twopence_ssh_transaction_free(struct twopence_ssh_transaction *trans)
{
  /* For now, nothing */
  free(trans);
}

static void
__twopence_ssh_exit_signal_callback(ssh_session session, ssh_channel channel, const char *signal, int core, const char *errmsg, const char *lang, void *userdata)
{
  struct twopence_ssh_target *handle = (struct twopence_ssh_target *) userdata;
  static const char *signames[NSIG] = {
	[SIGHUP] = "HUP",
	[SIGINT] = "INT",
	[SIGQUIT] = "QUIT",
	[SIGILL] = "ILL",
	[SIGTRAP] = "TRAP",
	[SIGABRT] = "ABRT",
	[SIGIOT] = "IOT",
	[SIGBUS] = "BUS",
	[SIGFPE] = "FPE",
	[SIGKILL] = "KILL",
	[SIGUSR1] = "USR1",
	[SIGSEGV] = "SEGV",
	[SIGUSR2] = "USR2",
	[SIGPIPE] = "PIPE",
	[SIGALRM] = "ALRM",
	[SIGTERM] = "TERM",
	[SIGSTKFLT] = "STKFLT",
	[SIGCHLD] = "CHLD",
	[SIGCONT] = "CONT",
	[SIGSTOP] = "STOP",
	[SIGTSTP] = "TSTP",
	[SIGTTIN] = "TTIN",
	[SIGTTOU] = "TTOU",
	[SIGURG] = "URG",
	[SIGXCPU] = "XCPU",
	[SIGXFSZ] = "XFSZ",
	[SIGVTALRM] = "VTALRM",
	[SIGPROF] = "PROF",
	[SIGWINCH] = "WINCH",
	[SIGIO] = "IO",
	[SIGPWR] = "PWR",
	[SIGSYS] = "SYS",
  };
  int signo;

  for (signo = 0; signo < NSIG; ++signo) {
    const char *name = signames[signo];

    if (name && !strcmp(name, signal)) {
      handle->exit_signal = signo;
      return;
    }
  }

  handle->exit_signal = -1;
}

static void
__twopence_ssh_init_callbacks(struct twopence_ssh_target *handle)
{
  struct ssh_channel_callbacks_struct *cb = &handle->callbacks;

  if (cb->size == 0) {
    cb->channel_exit_signal_function = __twopence_ssh_exit_signal_callback;
    ssh_callbacks_init(cb);
  }

  if (handle->channel == NULL)
    return;

  cb->userdata = handle;
  ssh_set_channel_callbacks(handle->channel, cb);
}

///////////////////////////// Middle layer //////////////////////////////////////

// Read the input from the keyboard or a pipe
static int
__twopence_ssh_read_input(struct twopence_ssh_transaction *trans)
{
  twopence_iostream_t *stream;
  char buffer[BUFFER_SIZE];
  int size, written;

  stream = trans->stdin.stream;
  if (stream == NULL || twopence_iostream_eof(stream)) {
    trans->stdin.stream = NULL;
    return 0;
  }

  // Read from stdin
  size = twopence_iostream_read(stream, buffer, BUFFER_SIZE);
  if (size < 0) {
    if (errno != EAGAIN)               // Error
      return -1;
    return 0;
  }
  if (size == 0) {
    /* EOF from local file */
    SSH_TRACE("%s: EOF\n", __func__);
    if (__twopence_ssh_channel_eof(trans->handle) == SSH_ERROR)
      return -1;
    trans->stdin.stream = NULL;
    return 0;
  }
  SSH_TRACE("%s: writing %d bytes to command\n", __func__, size);
  written = ssh_channel_write          // Data, forward it to the remote host
    (trans->channel, buffer, size);
  if (written != size)
    return -1;
  return 0;
}

static int
__twopence_ssh_stdin_cb(socket_t fd, int revents, void *userdata)
{
  struct pollfd *pfd = (struct pollfd *) userdata;

  SSH_TRACE("%s: revents=%d\n", __func__, revents);
  pfd->revents = revents;
  return 0;
}

static bool
__twopence_ssh_check_timeout(const struct timeval *now, const struct timeval *expires, int *msec)
{
    struct timeval until;
    long until_ms;

    if (timercmp(expires, now, <))
      return false;

    timersub(expires, now, &until);
    until_ms = 1000 * until.tv_sec + until.tv_usec / 1000;
    if (*msec < 0 || until_ms < *msec)
      *msec = until_ms;

    return true;
}


static int
__twopence_ssh_poll(struct twopence_ssh_transaction *trans)
{
  twopence_iostream_t *stream;
  ssh_event event;

  fflush(stdout);
  while ((stream = trans->stdin.stream) != NULL) {
    int n;

    n = twopence_iostream_poll(stream, &trans->stdin.pfd, POLLIN);
    if (n == 0) {
      /* Buffer iostreams return 0; which means it's either a buffer object
       * that has no open fd, or it's at EOF already.
       * In either case, we should try reading from this stream right away. */
      SSH_TRACE("%s: writing stdin synchronously to peer\n", __func__);
      if (__twopence_ssh_read_input(trans) < 0)
        return -1;
    }
    if (n < 0) {
      /* Close this iostream */
      SSH_TRACE("%s: stdin is at EOF\n", __func__);
      trans->at_eof[0] = true;
      break;
    }
    if (n > 0) {
      SSH_TRACE("%s: set up stdin for polling from fd %d\n", __func__, trans->stdin.pfd.fd);
      break;
    }
  }

  do {
    struct timeval now;
    char buffer[BUFFER_SIZE];
    int timeout;
    int size;
    int rc;

    if (trans->stdin.pfd.revents & (POLLIN|POLLHUP)) {
      SSH_TRACE("%s: trying to read some data from stdin\n", __func__);
      if (__twopence_ssh_read_input(trans) < 0)
        return -1;
    }
    if (trans->stdin.stream == NULL) {
      /* We received an EOF when trying to read from the stream */
      if (trans->stdin.pfd.fd >= 0) {
        SSH_TRACE("%s: stdin is at EOF\n", __func__);
        trans->stdin.pfd.fd = -1;
      }
      trans->stdin.stream = NULL;
      trans->at_eof[0] = true;
    }
    trans->stdin.pfd.revents = 0;

    if (ssh_channel_poll(trans->channel, 0) != 0) {
      SSH_TRACE("%s: trying to read some data from stdout\n", __func__);
      size = ssh_channel_read_nonblocking(trans->channel, buffer, sizeof(buffer), 0);
      if (size == SSH_ERROR)
        return -2;
      if (size == SSH_EOF) {
        SSH_TRACE("%s: stdout is at EOF\n", __func__);
	trans->at_eof[1] = true;
      }
      if (size > 0) {
        if (twopence_target_write(&trans->handle->base, TWOPENCE_STDOUT, buffer, size) < 0)
	  return -2;
      }
    }

    if (ssh_channel_poll(trans->channel, 1) != 0) {
      SSH_TRACE("%s: trying to read some data from stderr\n", __func__);
      size = ssh_channel_read_nonblocking(trans->channel, buffer, sizeof(buffer), 1);
      if (size == SSH_ERROR)
        return -2;
      if (size == SSH_EOF) {
        SSH_TRACE("%s: stderr is at EOF\n", __func__);
	trans->at_eof[2] = true;
      }
      if (size > 0) {
        if (twopence_target_write(&trans->handle->base, TWOPENCE_STDERR, buffer, size) < 0)
	  return -2;
      }
    }

    SSH_TRACE("eof=%d/%d/%d\n", trans->at_eof[0], trans->at_eof[1], trans->at_eof[2]);
    if (trans->at_eof[1] && trans->at_eof[2])
      break;

    gettimeofday(&now, NULL);
    timeout = -1;

    if (!__twopence_ssh_check_timeout(&now, &trans->command_timeout, &timeout))
      return -5;

    event = ssh_event_new();
    ssh_event_add_session(event, ssh_channel_get_session(trans->channel));
    if (trans->stdin.pfd.fd >= 0) {
      SSH_TRACE("poll on fd %d\n", trans->stdin.pfd.fd);
      ssh_event_add_fd(event, trans->stdin.pfd.fd, POLLIN, __twopence_ssh_stdin_cb, &trans->stdin.pfd);
    }

    SSH_TRACE("polling for events; timeout=%d\n", timeout);
    rc = ssh_event_dopoll(event, timeout);
    ssh_event_free(event);

    if (rc == SSH_ERROR)
      return -6;

    SSH_TRACE("ssh_event_dopoll() = %d\n", rc);
  } while (true);

  return 0;
}

static int
__twopence_ssh_read_results(struct twopence_ssh_target *handle, long timeout, ssh_channel channel)
{
  struct twopence_ssh_transaction *trans;
  int rv;

  trans = __twopence_ssh_transaction_new(handle, channel,
			  twopence_target_stream(&handle->base, TWOPENCE_STDIN),
			  timeout);

  rv = __twopence_ssh_poll(trans);
  __twopence_ssh_transaction_free(trans);

  return rv;
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
  handle->exit_signal = 0;

  __twopence_ssh_init_callbacks(handle);

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
      if (handle->exit_signal) {
	// mimic the behavior of the test server for now.
	// in the long run, better reporting would be great.
	status_ret->major = EFAULT;
	status_ret->minor = handle->exit_signal;
      } else {
        status_ret->minor = ssh_channel_get_exit_status(channel);
      }
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
__twopence_ssh_extract_ssh(struct twopence_ssh_target *handle, twopence_file_xfer_t *xfer, twopence_status_t *status)
{
  ssh_session session = handle->session;
  ssh_scp scp;
  int size, rc;

  // Create and initialize a SCP session
  scp = ssh_scp_new(session, SSH_SCP_READ, xfer->remote.name);
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
    status->major = ssh_get_error_code(session);
    ssh_scp_close(scp);
    ssh_scp_free(scp);
    return TWOPENCE_RECEIVE_FILE_ERROR;
  }
  size = ssh_scp_request_get_size(scp);
  if (!size) return 0;

  // Accept the transfer request
  if (ssh_scp_accept_request(scp) != SSH_OK)
  {
    status->major = ssh_get_error_code(session);
    ssh_scp_close(scp);
    ssh_scp_free(scp);
    return TWOPENCE_RECEIVE_FILE_ERROR;
  }

  // Receive the file
  rc = __twopence_ssh_receive_file
        (handle, xfer->local_stream, scp, size, &status->major);
  if (rc < 0)
  {
    ssh_scp_close(scp);
    ssh_scp_free(scp);
    return rc;
  }

  // Check for proper termination
  if (ssh_scp_pull_request(scp) != SSH_SCP_REQUEST_EOF)
  {
    status->major = ssh_get_error_code(session);
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
static struct twopence_target *
twopence_ssh_init(const char *arg)
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
    twopence_iostream_wrap_buffer(bp, false, &tmp_xfer.local_stream);
    rc = __twopence_ssh_inject_ssh(handle, &tmp_xfer, dirname, basename, status);
    twopence_iostream_free(tmp_xfer.local_stream);
  } else {
    rc = __twopence_ssh_inject_ssh(handle, xfer,dirname, basename,  status);
  }

  if (rc == 0 && (status->major != 0 || status->minor != 0))
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
		twopence_file_xfer_t *xfer, twopence_status_t *status)
{
  struct twopence_ssh_target *handle = (struct twopence_ssh_target *) opaque_handle;
  int rc;

  // Connect to the remote host
  if (__twopence_ssh_connect_ssh(handle, xfer->user) < 0)
    return TWOPENCE_OPEN_SESSION_ERROR;

  // Extract the file
  rc = __twopence_ssh_extract_ssh(handle, xfer, status);
  if (rc == 0 && (status->major != 0 || status->minor != 0))
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

	.init = twopence_ssh_init,
	.run_test = twopence_ssh_run_test,
	.inject_file = twopence_ssh_inject_file,
	.extract_file = twopence_ssh_extract_file,
	.exit_remote = twopence_ssh_exit_remote,
	.interrupt_command = twopence_ssh_interrupt_command,
	.end = twopence_ssh_end,
};
