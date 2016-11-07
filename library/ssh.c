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
#include "utils.h"

#define BUFFER_SIZE 16384              // Size in bytes of the work buffer for receiving data from the remote host


typedef struct twopence_ssh_transaction twopence_ssh_transaction_t;

// This structure encapsulates in an opaque way the behaviour of the library
// It is not 100 % opaque, because it is publicly known that the first field is the plugin type
struct twopence_ssh_target
{
  struct twopence_target base;

  ssh_session template;

  ssh_event event;

  /* Current command being executed.
   * We have one foreground command (which will receive Ctrl-C interrupts),
   * and any number of backgrounded commands.
   */
  struct {
    twopence_ssh_transaction_t *foreground;

    twopence_ssh_transaction_t *running;
    twopence_ssh_transaction_t *done;

    unsigned int next_pid;
  } transactions;
};

struct twopence_ssh_transaction {
  twopence_ssh_transaction_t *next;

  struct twopence_ssh_target *handle;

  /* This is a twopence-internal "pid" that has no relation whatsoever
   * with any system PIDs */
  unsigned int		pid;

  ssh_session		session;
  ssh_channel		channel;
  ssh_event		event;

  /* Set to true when we have an EOF packet from remote */
  bool			eof_seen;

  /* Set to true when we have an exit status from remote */
  bool			have_exit_status;

  /* Set to true when the transaction is done. */
  bool			done;

  /* This is used by the lower-level routines to report exceptions
   * while processing the transaction. The value of the exception
   * is a twopence error code.
   */
  int			exception;

  /* This is where we store the command's status */
  twopence_status_t	status;

  struct {
    twopence_iostream_t *stream;
    int			fd;
    bool		eof;
    bool		propagate_eof;
    int			was_blocking;
  } stdin;

  struct twopence_ssh_output {
    twopence_iostream_t *stream;
  } stdout, stderr;

  struct timeval	command_timeout;

  bool			eof_sent;
  bool			use_tty;
  bool			interrupted;

  struct {
    bool		waiting;	/* true iff we're in wait_for_output */
    unsigned int	nreceived;	/* number of bytes received */
    const struct timeval *timeout;	/* how long to wait for more input */
  } chat;

  /* Right now, we need the callbacks for exactly one reason -
   * to catch the exit signal of the remote process.
   * When a command dies from a signal, libssh will always report
   * an exit code of -1 (SSH_ERROR), and the only way to catch what
   * really happens is by hooking up this callback.
   */
  struct ssh_channel_callbacks_struct callbacks;
};

typedef struct twopence_scp_transaction twopence_scp_transaction_t;
struct twopence_scp_transaction {
  struct twopence_ssh_target *handle;

  ssh_session		session;
  ssh_scp		scp;

  twopence_iostream_t *	local_stream;
  long			remaining;

  /* Used for printing dots */
  twopence_iostream_t *	dots_stream;
};

extern const struct twopence_plugin twopence_ssh_ops;

static bool		__twopence_ssh_interrupted;

static ssh_session	__twopence_ssh_open_session(const struct twopence_ssh_target *, const char *);
static void		__twopence_ssh_transaction_detach_stdin(twopence_ssh_transaction_t *trans);
static int		__twopence_ssh_interrupt_ssh(struct twopence_ssh_target *);

///////////////////////////// Lower layer ///////////////////////////////////////

/*
 * This is really just a helper for printing dots to stdout
 */
static inline void
__twopence_ssh_putc(twopence_iostream_t *stream, char c)
{
  if (stream)
    twopence_iostream_putc(stream, c);
}

/*
 * SSH Transaction functions
 */

/*
 * __twopence_ssh_transaction_send_eof
 *
 * This is called when we find that the local stream connected to the remote stdin
 * has been closed. Inform the remote.
 */
static int
__twopence_ssh_transaction_send_eof(twopence_ssh_transaction_t *trans)
{
  int rc = SSH_OK;

  if (trans->channel == NULL || trans->eof_sent)
    return SSH_OK;
  if (trans->use_tty && !trans->eof_seen)
    rc = ssh_channel_write(trans->channel, "\004", 1);
  if (rc == SSH_OK)
    rc = ssh_channel_send_eof(trans->channel);
  if (rc == SSH_OK)
    trans->eof_sent = true;
  return rc;
}

/*
 * Tear down the SSH connection and all related stuff.
 * Make sure we remove ourselves from the event handle.
 */
static void
__twopence_ssh_transaction_close_channel(twopence_ssh_transaction_t *trans)
{
  if (trans->event) {
    if (trans->session)
      ssh_event_remove_session(trans->event, trans->session);
    if (trans->stdin.fd >= 0) {
      ssh_event_remove_fd(trans->event, trans->stdin.fd);
      trans->stdin.fd = -1;
    }
    trans->event = NULL;
  }

  /*
   * In absence of a real signal delivery mechanism, we have to forcefully
   * disconnect after interrupting the command.
   *
   * Simply calling ssh_channel_close doesn't help at all, because that
   * will also try to shut down the command in an orderly fashion and
   * collect its exit status. So it will just hang.
   */
  if (trans->interrupted) {
    if (trans->session) {
      ssh_silent_disconnect(trans->session);
      trans->channel = NULL;
    }
  } else {
    if (trans->channel) {
      ssh_channel_close(trans->channel);
      ssh_channel_free(trans->channel);
      trans->channel = NULL;
    }

    if (trans->session)
      ssh_disconnect(trans->session);
  }

  if (trans->session) {
    ssh_disconnect(trans->session);
    ssh_free(trans->session);
    trans->session = NULL;
  }
}

/*
 * Create a new SSH (command) transaction
 */
static twopence_ssh_transaction_t *
__twopence_ssh_transaction_new(struct twopence_ssh_target *handle, unsigned long timeout)
{
  twopence_ssh_transaction_t *trans;

  trans = twopence_calloc(1, sizeof(*trans));
  if (trans == NULL)
    return NULL;

  trans->handle = handle;

  gettimeofday(&trans->command_timeout, NULL);
  trans->command_timeout.tv_sec += timeout;

  trans->stdin.fd = -1;

  return trans;
}

/*
 * Delete a transaction object
 */
void
__twopence_ssh_transaction_free(struct twopence_ssh_transaction *trans)
{
  twopence_iostream_t *stream;

  /* Reset stdin to original behavior.
   * I'm not convinced that this still makes a lot of sense, given that
   * (a) we have now changed everything to ssh_poll, and
   * (b) we're executing several transactions concurrently
   * The latter shouldn't be a problem in theory, because only the foreground
   * process should be allowed to connect to stdin.
   */
  if ((stream = trans->stdin.stream) != NULL)
    if (trans->stdin.was_blocking >= 0)
      twopence_iostream_set_blocking(stream, trans->stdin.was_blocking);

  __twopence_ssh_transaction_close_channel(trans);
  free(trans);
}

/*
 * When a transaction fails due to some protocol/transport layer problems,
 * we store the error code in trans->exception and mark it as done.
 */
static inline void
__twopence_ssh_transaction_fail(twopence_ssh_transaction_t *trans, int error)
{
  if (!trans->exception)
    trans->exception = error;
  trans->done = true;
}

static inline void
__twopence_ssh_transaction_set_exit_status(twopence_ssh_transaction_t *trans, int exit_status)
{
  trans->status.major = 0;
  trans->status.minor = exit_status;
  trans->have_exit_status = true;
}

static inline void
__twopence_ssh_transaction_set_exit_signal(twopence_ssh_transaction_t *trans, int exit_signal)
{
  trans->status.major = EFAULT;
  trans->status.minor = exit_signal;
  trans->have_exit_status = true;
}

static void
__twopence_ssh_transaction_setup_stdin(twopence_ssh_transaction_t *trans, twopence_iostream_t *stdin_stream, bool propagate)
{
  /* Set stdin to non-blocking IO */
  trans->stdin.was_blocking = twopence_iostream_set_blocking(stdin_stream, false);
  trans->stdin.stream = stdin_stream;
  trans->stdin.propagate_eof = propagate;
  trans->stdin.eof = false;
  trans->stdin.fd = -1;
}

static void
__twopence_ssh_transaction_setup_stdio(twopence_ssh_transaction_t *trans,
		twopence_iostream_t *stdin_stream,
		twopence_iostream_t *stdout_stream,
		twopence_iostream_t *stderr_stream)
{
  if (stdin_stream)
    __twopence_ssh_transaction_setup_stdin(trans, stdin_stream, true);

  trans->stdout.stream = stdout_stream;
  trans->stderr.stream = stderr_stream;
}

/*
 * The following functions are somewhat complicated, but provide the necessary machinery to discover
 * processes that were killed via a signal
 */
static void
__twopence_ssh_exit_signal_callback(ssh_session session, ssh_channel channel, const char *signal, int core, const char *errmsg, const char *lang, void *userdata)
{
  twopence_ssh_transaction_t *trans = (twopence_ssh_transaction_t *) userdata;
  int signo;

  signo = twopence_name_to_signal(signal);
  if (signo < 0) {
    twopence_log_error("process %d exited with unknown signal %s; mapping to SIGIO", trans->pid, signal);
    signo = SIGIO;
  }
  __twopence_ssh_transaction_set_exit_signal(trans, signo);
}

static void
__twopence_ssh_exit_status_callback(ssh_session session, ssh_channel channel, int exit_status, void *userdata)
{
  twopence_ssh_transaction_t *trans = (twopence_ssh_transaction_t *) userdata;

  trans->have_exit_status = true;
  trans->status.major = 0;
  trans->status.minor = exit_status;

  /* No longer try to forward any data from stdin to the remote. It's gone */
  __twopence_ssh_transaction_detach_stdin(trans);
}

static int
__twopence_ssh_data_callback(ssh_session session, ssh_channel channel, void *data, uint32_t len, int is_stderr, void *userdata)
{
  twopence_ssh_transaction_t *trans = (twopence_ssh_transaction_t *) userdata;
  struct twopence_ssh_output *out;

  twopence_debug("%d: channel received %u bytes on %s", trans->pid, len, is_stderr? "stderr" : "stdout");
  out = is_stderr? &trans->stderr : &trans->stdout;
  if (len > 0 && out->stream) {
    if (twopence_iostream_write(out->stream, data, len) < 0) {
      __twopence_ssh_transaction_fail(trans, TWOPENCE_RECEIVE_RESULTS_ERROR);
      return SSH_ERROR;
    }
    trans->chat.nreceived += len;
  }
  return len;
}

static void
__twopence_ssh_eof_callback(ssh_session session, ssh_channel channel, void *userdata)
{
  twopence_ssh_transaction_t *trans = (twopence_ssh_transaction_t *) userdata;

  twopence_debug("%d: channel is at eof", trans->pid);
  trans->eof_seen = true;
}

static void
__twopence_ssh_close_callback(ssh_session session, ssh_channel channel, void *userdata)
{
  twopence_ssh_transaction_t *trans = (twopence_ssh_transaction_t *) userdata;

  twopence_debug("%d: channel was closed", trans->pid);
}

static void
__twopence_ssh_init_callbacks(twopence_ssh_transaction_t *trans)
{
  struct ssh_channel_callbacks_struct *cb = &trans->callbacks;

  if (cb->size == 0) {
    cb->channel_exit_signal_function = __twopence_ssh_exit_signal_callback;
    cb->channel_exit_status_function = __twopence_ssh_exit_status_callback;
    cb->channel_close_function = __twopence_ssh_close_callback;
    cb->channel_data_function = __twopence_ssh_data_callback;
    cb->channel_eof_function = __twopence_ssh_eof_callback;
    ssh_callbacks_init(cb);
  }

  if (trans->channel == NULL)
    return;

  cb->userdata = trans;
  ssh_set_channel_callbacks(trans->channel, cb);
}

static int
__twopence_ssh_transaction_open_session(twopence_ssh_transaction_t *trans, const char *username)
{
  if (!trans->handle)
    return TWOPENCE_OPEN_SESSION_ERROR;

  trans->session = __twopence_ssh_open_session(trans->handle, username);
  if (trans->session == NULL)
    return TWOPENCE_OPEN_SESSION_ERROR;

  trans->channel = ssh_channel_new(trans->session);
  if (trans->channel == NULL)
    return TWOPENCE_OPEN_SESSION_ERROR;

  if (ssh_channel_open_session(trans->channel) != SSH_OK)
    return TWOPENCE_OPEN_SESSION_ERROR;

  return 0;
}

static int
__twopence_ssh_transaction_execute_command(twopence_ssh_transaction_t *trans, twopence_command_t *cmd)
{
  if (trans->channel == NULL)
    return TWOPENCE_OPEN_SESSION_ERROR;

  __twopence_ssh_init_callbacks(trans);

  // Request that the command be run inside a tty
  if (cmd->request_tty) {
    if (ssh_channel_request_pty(trans->channel) != SSH_OK)
      return TWOPENCE_OPEN_SESSION_ERROR;
    trans->use_tty = true;
  }

  if (cmd->env.count) {
    unsigned int i;

    for (i = 0; i < cmd->env.count; ++i) {
      char *var = cmd->env.array[i];
      char *value;
      int rc;

      if ((value = strchr(var, '=')) == NULL)
        continue;

      *value++ = '\0';
      rc = ssh_channel_request_env(trans->channel, var, value);
      value[-1] = '=';

      /* Given that sshd is probably configured in a way to not allow a lot of
       * environment variables, we do not make this a fatal error but warn about
       * it instead. */
      if (rc != SSH_OK)
        twopence_log_warning("SSH server did not accept environment variable %s (see sshd_config(5), AcceptEnv)", var);
    }
  }

  __twopence_ssh_transaction_setup_stdio(trans,
		  cmd->background? NULL : &cmd->iostream[TWOPENCE_STDIN],
		  &cmd->iostream[TWOPENCE_STDOUT],
		  &cmd->iostream[TWOPENCE_STDERR]);

  trans->stdin.propagate_eof = !cmd->keepopen_stdin;

  // Execute the command
  if (ssh_channel_request_exec(trans->channel, cmd->command) != SSH_OK)
    return TWOPENCE_SEND_COMMAND_ERROR;

  return 0;
}

static int
__twopence_ssh_transaction_get_exit_status(twopence_ssh_transaction_t *trans)
{
  twopence_status_t *status = &trans->status;

  if (trans->channel == NULL) {
    __twopence_ssh_transaction_fail(trans, TWOPENCE_TRANSPORT_ERROR);
    return -1;
  }

  /*
   * In absence of a real signal delivery mechanism, we have to
   * fake the exit signal here.
   */
  if (trans->interrupted) {
    assert(trans->status.major == EFAULT);
    return 0;
  }

  /* If we haven't done so, send the EOF now. */
  if (__twopence_ssh_transaction_send_eof(trans) == SSH_ERROR) {
    __twopence_ssh_transaction_fail(trans, TWOPENCE_RECEIVE_RESULTS_ERROR);
    return -1;
  }

  if (!trans->have_exit_status) {
    /* Get the exit status as reported by the SSH server.
     * If the command exited with a signal, this will be SSH_ERROR;
     * but the exit_signal_callback will be invoked, which allows us
     * to snarf the exit_signal
     */
    twopence_log_error("transaction %d has no exit status", trans->pid);
    status->major = 0;
    (void) ssh_channel_get_exit_status(trans->channel);
    if (!trans->have_exit_status) {
      twopence_log_error("ssh_channel_get_exit_status didn't set the exit status either, faking it");
      trans->status.major = EIO;
    }
  }

  twopence_debug("exit status is %d/%d\n", status->major, status->minor);
  return 0;
}

static void
__twopence_ssh_fake_exit_signal(twopence_ssh_transaction_t *trans, int signal)
{
  __twopence_ssh_transaction_set_exit_signal(trans, signal);
  trans->interrupted = true;
  trans->done = true;
}

static void
__twopence_ssh_transaction_detach_stdin(twopence_ssh_transaction_t *trans)
{
  if (trans->stdin.fd >= 0) {
    ssh_event_remove_fd(trans->handle->event, trans->stdin.fd);
    trans->stdin.fd = -1;
  }
}

static int
__twopence_ssh_transaction_mark_stdin_eof(twopence_ssh_transaction_t *trans)
{
  twopence_debug("%s: stdin is at EOF\n", __func__);
  trans->stdin.eof = true;

  /* When executing a chat script, we do not want to close the
   * remote command's EOF as soon as we reach the end of the send
   * buffer - the caller may write more data to the buffer later.
   */
  if (!trans->stdin.propagate_eof)
    return 0;

  if (__twopence_ssh_transaction_send_eof(trans) == SSH_ERROR)
    return -1;

  __twopence_ssh_transaction_detach_stdin(trans);
  return 0;
}

/*
 * Read data from stdin and forward it to the remote command
 */
static int
__twopence_ssh_transaction_forward_stdin(twopence_ssh_transaction_t *trans)
{
  twopence_iostream_t *stream;
  char buffer[BUFFER_SIZE];
  int size, written;

  if (trans->stdin.eof)
    return 0;

  stream = trans->stdin.stream;
  if (stream == NULL || twopence_iostream_eof(stream))
    return __twopence_ssh_transaction_mark_stdin_eof(trans);

  // Read from stdin
  size = twopence_iostream_read(stream, buffer, BUFFER_SIZE);
  if (size < 0) {
    if (errno != EAGAIN)               // Error
      return -1;
    return 0;
  }
  if (size == 0) {
    /* EOF from local file */
    return __twopence_ssh_transaction_mark_stdin_eof(trans);
  }

  twopence_debug("%s: writing %d bytes to command\n", __func__, size);
  written = ssh_channel_write(trans->channel, buffer, size);
  if (written != size)
    return -1;
  return 0;
}

/*
 * Write all data pending on stdin to the remote.
 * This function is only called when stdin is connected to a buffer
 * or similar.
 */
static int
__twopence_ssh_transaction_drain_stdin(twopence_ssh_transaction_t *trans)
{
  while (!trans->stdin.eof) {
    if (__twopence_ssh_transaction_forward_stdin(trans) < 0) {
      __twopence_ssh_transaction_fail(trans, TWOPENCE_FORWARD_INPUT_ERROR);
      return -1;
    }
  }

  return 0;
}

static int
__twopence_ssh_stdin_cb(socket_t fd, int revents, void *userdata)
{
  twopence_ssh_transaction_t *trans = (twopence_ssh_transaction_t *) userdata;

  twopence_debug("%s: can read data on fd %d\n", __func__, fd);
  if (__twopence_ssh_transaction_forward_stdin(trans) < 0)
    __twopence_ssh_transaction_fail(trans, TWOPENCE_FORWARD_INPUT_ERROR);

  return 0;
}

static int
__twopence_ssh_transaction_enable_poll(ssh_event event, twopence_ssh_transaction_t *trans)
{
  twopence_iostream_t *stream;

  trans->event = event;

  ssh_event_add_session(event, trans->session);

  if ((stream = trans->stdin.stream) != NULL && !twopence_iostream_eof(stream)) {
    trans->stdin.fd = twopence_iostream_getfd(stream);
    if (trans->stdin.fd < 0) {
      twopence_debug("%s: writing stdin synchronously to peer\n", __func__);
      if (__twopence_ssh_transaction_drain_stdin(trans) < 0)
	return -1;
    } else {
      ssh_event_add_fd(event, trans->stdin.fd, POLLIN, __twopence_ssh_stdin_cb, trans);
    }
  }

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
__twopence_ssh_poll(struct twopence_ssh_target *handle)
{
  ssh_event event = handle->event;
  twopence_ssh_transaction_t *trans;

  fflush(stdout);
  do {
    struct timeval now;
    int timeout;
    int rc;

    twopence_debug("%s: try to do some I/O", __func__);
    for (trans = handle->transactions.running; trans; trans = trans->next) {
      /* Note: the transaction may have been interrupted by twopence_ssh_interrupt_command().
       * In this case, trans->done will be true.
       */
      if (trans->eof_seen && trans->have_exit_status)
        trans->done = true;

      if (trans->done) {
	/* FIXME: this is blocking, which is bad. A program may close its standard
	 * I/O channels and still keep on running for a long time.
	 * We really need to tie into the exit status callback from SSH
	 */
        return __twopence_ssh_transaction_get_exit_status(trans);
      }

      if (trans->chat.waiting) {
        if (trans->chat.nreceived)
	  return trans->chat.nreceived;
	if (trans->eof_seen)
	  return 0;
      }
    }

    gettimeofday(&now, NULL);
    timeout = -1;

    for (trans = handle->transactions.running; trans; trans = trans->next) {
      if (!__twopence_ssh_check_timeout(&now, &trans->command_timeout, &timeout)) {
        __twopence_ssh_transaction_fail(trans, TWOPENCE_COMMAND_TIMEOUT_ERROR);
        return 0;
      }
      if (trans->chat.timeout
       && !__twopence_ssh_check_timeout(&now, trans->chat.timeout, &timeout)) {
	/* Do not fail the transaction, just return a timeout */
	return TWOPENCE_COMMAND_TIMEOUT_ERROR;
      }
    }

    twopence_debug("polling for events; timeout=%d\n", timeout);
    rc = ssh_event_dopoll(event, timeout);

    if (__twopence_ssh_interrupted) {
      twopence_debug("ssh_event_dopoll() interrupted by signal");
      __twopence_ssh_interrupted = false;
      continue;
    }

    if (rc == SSH_ERROR) {
      twopence_debug("ssh_event_dopoll() returns error");
      return TWOPENCE_INTERNAL_ERROR;
    }
  } while (true);

  return 0;
}

static void
__twopence_ssh_transaction_add_running(struct twopence_ssh_target *handle, twopence_ssh_transaction_t *trans)
{
  trans->next = handle->transactions.running;
  handle->transactions.running = trans;

  trans->pid = handle->transactions.next_pid++;
}

static inline twopence_ssh_transaction_t *
__twopence_ssh_get_transaction(twopence_ssh_transaction_t **pos, unsigned int want_pid, bool unlink)
{
  twopence_ssh_transaction_t *trans;

  while ((trans = *pos) != NULL) {
    if (want_pid == 0 || trans->pid == want_pid)
      break;

    pos = &trans->next;
  }

  if (trans == NULL)
    return NULL;

  if (unlink) {
    *pos = trans->next;
    trans->next = NULL;
  }

  return trans;
}

static twopence_ssh_transaction_t *
__twopence_ssh_transaction_by_pid(struct twopence_ssh_target *handle, unsigned int want_pid)
{
  twopence_ssh_transaction_t *result = NULL;

  if (want_pid != 0) {
    result = __twopence_ssh_get_transaction(&handle->transactions.running, want_pid, false);
    if (result == NULL)
      result = __twopence_ssh_get_transaction(&handle->transactions.done, want_pid, false);
  }
  return result;
}

static twopence_ssh_transaction_t *
__twopence_ssh_get_completed_transaction(struct twopence_ssh_target *handle, unsigned int want_pid)
{
  return __twopence_ssh_get_transaction(&handle->transactions.done, want_pid, true);
}

static int
__twopence_ssh_reap_completed(struct twopence_ssh_target *handle)
{
  twopence_ssh_transaction_t **pos, **tail, *trans;
  int nreaped = 0;

  for (tail = &handle->transactions.done; *tail != NULL; tail = &(*tail)->next)
    ;

  pos = &handle->transactions.running;
  while ((trans = *pos) != NULL) {
    if (trans->done) {
      *pos = trans->next;
      *tail = trans;
      trans->next = NULL;
      tail = &trans->next;

      __twopence_ssh_transaction_close_channel(trans);
      nreaped ++;
    } else {
      pos = &trans->next;
    }
  }

  return nreaped;
}

static void
__twopence_ssh_cancel_transactions(struct twopence_ssh_target *handle, int error)
{
  twopence_ssh_transaction_t *trans;

  /* Flag all pending transactions as having encountered a transport error */
  for (trans = handle->transactions.running; trans; trans = trans->next)
    __twopence_ssh_transaction_fail(trans, TWOPENCE_TRANSPORT_ERROR);

  /* Transfer the whole lot from running to done queue */
  __twopence_ssh_reap_completed(handle);
}

// Send a file in chunks through SCP
//
// Returns 0 if everything went fine, or a negative error code if failed
static int
__twopence_ssh_send_file(twopence_scp_transaction_t *trans, twopence_status_t *status)
{
  char buffer[BUFFER_SIZE];
  int size, received;

  while (trans->remaining > 0) {
    size = trans->remaining;
    if (size > BUFFER_SIZE)
      size = BUFFER_SIZE;

    received = twopence_iostream_read(trans->local_stream, buffer, size);
    if (received != size)
    {
      __twopence_ssh_putc(trans->dots_stream, '\n');
      return TWOPENCE_LOCAL_FILE_ERROR;
    }

    if (ssh_scp_write (trans->scp, buffer, size) != SSH_OK)
    {
      status->major = ssh_get_error_code(trans->session);
      __twopence_ssh_putc(trans->dots_stream, '\n');
      return TWOPENCE_SEND_FILE_ERROR;
    }

    __twopence_ssh_putc(trans->dots_stream, '.');     // Progression dots
    trans->remaining -= size;                 // That much we don't need to send anymore
  }
  __twopence_ssh_putc(trans->dots_stream, '\n');
  return 0;
}

// Receive a file in chunks through SCP
//
// Returns 0 if everything went fine, or a negative error code if failed
static int
__twopence_ssh_receive_file(twopence_scp_transaction_t *trans, twopence_status_t *status)
{
  char buffer[BUFFER_SIZE];
  int size, received, written;

  while (trans->remaining > 0) {
    size = trans->remaining;
    if (size > BUFFER_SIZE)
      size = BUFFER_SIZE;

    received = ssh_scp_read(trans->scp, buffer, size);
    if (received != size)
    {
      status->major = ssh_get_error_code(trans->session);
      __twopence_ssh_putc(trans->dots_stream, '\n');
      return TWOPENCE_RECEIVE_FILE_ERROR;
    }

    written = twopence_iostream_write(trans->local_stream, buffer, size);
    if (written != size)
    {
      __twopence_ssh_putc(trans->dots_stream, '\n');
      return TWOPENCE_LOCAL_FILE_ERROR;
    }

    __twopence_ssh_putc(trans->dots_stream, '.');     // Progression dots
    trans->remaining -= size;                 // That's that much less to receive
  }
  __twopence_ssh_putc(trans->dots_stream, '\n');
  return 0;
}

///////////////////////////// Top layer /////////////////////////////////////////

// Open a SSH session as some user
//
// Returns 0 if everything went fine, a negative error code otherwise
static ssh_session
__twopence_ssh_open_session(const struct twopence_ssh_target *handle, const char *username)
{
  ssh_session session;

  if (username == NULL)
    username = "root";

  // Create a new session based on the session template
  session = ssh_new();                 // FIXME: according to the documentation, we should not allocate 'session' ourselves (?)
  if (session == NULL)
    return NULL;
  if (ssh_options_copy(handle->template, &session) < 0)
  {
    ssh_free(session);
    return NULL;
  }

  // Store the username
  if (ssh_options_set(session, SSH_OPTIONS_USER, username) < 0)
  {
    ssh_free(session);
    return NULL;
  }

  if (twopence_debug_level > 1) {
    int tracing = SSH_LOG_DEBUG;

    if (twopence_debug_level > 2)
      tracing = SSH_LOG_TRACE; /* even more verbose */

    if (ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &tracing) < 0)
      twopence_debug("warning: unable to set ssh log verbosity to %d. bummer...", tracing);
  }

  // Connect to the server
  if (ssh_connect(session) != SSH_OK)
  {
    ssh_free(session);
    return NULL;
  }

  // Authenticate with our private key, with no passphrase
  // That's the only available method, given that we are in the context of testing
  // For safety reasons, do not use such private keys with no passphrases to access production systems
  if (ssh_userauth_autopubkey(session, NULL) != SSH_AUTH_SUCCESS)
  {
    ssh_disconnect(session);
    ssh_free(session);
    return NULL;
  }

  return session;
}

// Submit a command to the remote host
//
// Returns 0 if everything went fine, a negative error code otherwise
static int
__twopence_ssh_command_ssh
    (struct twopence_ssh_target *handle, twopence_command_t *cmd, twopence_status_t *status_ret)
{
  twopence_ssh_transaction_t *trans = NULL;
  int rc;

  trans = __twopence_ssh_transaction_new(handle, cmd->timeout);
  if (trans == NULL)
    return TWOPENCE_OPEN_SESSION_ERROR;

  rc = __twopence_ssh_transaction_open_session(trans, cmd->user);
  if (rc != 0) {
    __twopence_ssh_transaction_free(trans);
    return rc;
  }

  rc = __twopence_ssh_transaction_execute_command(trans, cmd);
  if (rc != 0) {
    __twopence_ssh_transaction_free(trans);
    return rc;
  }

  __twopence_ssh_transaction_add_running(handle, trans);
  __twopence_ssh_transaction_enable_poll(handle->event, trans);

  if (cmd->background)
    return trans->pid;

  handle->transactions.foreground = trans;
  do {
    /* Process SSH I/O for all active commands.
     * When this function returns, at least one transaction has
     * finished, either by exiting or by an exception.
     */
    rc = __twopence_ssh_poll(handle);

    /* If this fails, this always denotes an internal error. */
    if (rc < 0) {
      handle->transactions.foreground = NULL;
      return rc;
    }

    if (!__twopence_ssh_reap_completed(handle))
      return TWOPENCE_INTERNAL_ERROR;
  } while (!__twopence_ssh_get_completed_transaction(handle, trans->pid));

  if (trans->exception) {
    rc = trans->exception;
  } else {
    *status_ret = trans->status;
    rc = 0;
  }

  handle->transactions.foreground = NULL;

  /* We're done with this transaction. Nuke it */
  __twopence_ssh_transaction_free(trans);

  return rc;
}

/*
 * SCP transaction functions
 */
static void
twopence_scp_transfer_init(twopence_scp_transaction_t *state, struct twopence_ssh_target *handle)
{
  memset(state, 0, sizeof(*state));
  state->handle = handle;
}

static void
twopence_scp_transfer_destroy(twopence_scp_transaction_t *trans)
{
  if (trans->scp) {
    ssh_scp_close(trans->scp);
    ssh_scp_free(trans->scp);
    trans->scp = NULL;
  }
  if (trans->session) {
    ssh_disconnect(trans->session);
    ssh_free(trans->session);
    trans->session = NULL;
  }
  if (trans->dots_stream) {
    twopence_iostream_free(trans->dots_stream);
    trans->dots_stream = NULL;
  }
}

static void
twopence_scp_transfer_print_dots(twopence_scp_transaction_t *state)
{
  twopence_iostream_wrap_fd(1, false, &state->dots_stream);
}

static int
twopence_scp_transfer_open_session(twopence_scp_transaction_t *trans, const char *username)
{
  trans->session = __twopence_ssh_open_session(trans->handle, username);
  if (trans->session == NULL)
    return TWOPENCE_OPEN_SESSION_ERROR;

  return 0;
}

static int
twopence_scp_transfer_init_copy(twopence_scp_transaction_t *trans, int direction, const char *remote_name)
{
  trans->scp = ssh_scp_new(trans->session, direction, remote_name);
  if (trans->scp == NULL)
    return TWOPENCE_OPEN_SESSION_ERROR;
  if (ssh_scp_init(trans->scp) != SSH_OK)
    return TWOPENCE_OPEN_SESSION_ERROR;

  return 0;
}

static bool
__twopence_ssh_check_remote_dir(ssh_session session, const char *remote_dirname)
{
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
__twopence_ssh_inject_ssh(twopence_scp_transaction_t *trans, twopence_file_xfer_t *xfer,
		const char *remote_dirname, const char *remote_basename,
		twopence_status_t *status)
{
  long filesize;
  int rc;

  filesize = twopence_iostream_filesize(xfer->local_stream);
  assert(filesize >= 0);

  /* Unfortunately, we have to make sure the remote directory exists.
   * In openssh-6.2p2 (and maybe others), if you try to create file
   * "foo" inside non-existant directory "/bar" will result in the
   * creation of regular file "/bar" and upload the content there.
   */
  if (!__twopence_ssh_check_remote_dir(trans->session, remote_dirname))
    return TWOPENCE_SEND_FILE_ERROR;

  if ((rc = twopence_scp_transfer_init_copy(trans, SSH_SCP_WRITE, remote_dirname)) < 0)
    return rc;

  // Tell the remote host about the file size
  if (ssh_scp_push_file(trans->scp, remote_basename, filesize, xfer->remote.mode) != SSH_OK)
  {
    status->major = ssh_get_error_code(trans->session);
    return TWOPENCE_SEND_FILE_ERROR;
  }

  trans->local_stream = xfer->local_stream;
  trans->remaining = filesize;

  // Send the file
  return __twopence_ssh_send_file(trans, status);
}

// Extract a file from the remote host through SSH
//
// Returns 0 if everything went fine
static int
__twopence_ssh_extract_ssh(twopence_scp_transaction_t *trans, twopence_file_xfer_t *xfer, twopence_status_t *status)
{
  int size, rc;

  if ((rc = twopence_scp_transfer_init_copy(trans, SSH_SCP_READ, xfer->remote.name)) < 0)
    return rc;

  // Get the file size from the remote host
  if (ssh_scp_pull_request(trans->scp) != SSH_SCP_REQUEST_NEWFILE)
    goto receive_file_error;
  size = ssh_scp_request_get_size(trans->scp);
  if (!size)
    return 0;

  // Accept the transfer request
  if (ssh_scp_accept_request(trans->scp) != SSH_OK)
    goto receive_file_error;

  trans->local_stream = xfer->local_stream;
  trans->remaining = size;

  // Receive the file
  rc = __twopence_ssh_receive_file(trans, status);
  if (rc < 0)
    return rc;

  // Check for proper termination
  if (ssh_scp_pull_request(trans->scp) != SSH_SCP_REQUEST_EOF)
    goto receive_file_error;

  return 0;

receive_file_error:
  status->major = ssh_get_error_code(trans->session);
  return TWOPENCE_RECEIVE_FILE_ERROR;
}

// Interrupt current command
//
// Returns 0 if everything went fine, or a negative error code if failed
static int
__twopence_ssh_interrupt_ssh(struct twopence_ssh_target *handle)
{
  twopence_ssh_transaction_t *trans;
  ssh_channel channel = NULL;

  if ((trans = handle->transactions.foreground) == NULL
   || (channel = trans->channel) == NULL)
    return TWOPENCE_OPEN_SESSION_ERROR;

#if 0
  // This is currently completly useless with OpenSSH
  // (see https://bugzilla.mindrot.org/show_bug.cgi?id=1424)
  if (ssh_channel_request_send_signal(channel, "INT") != SSH_OK)
    return TWOPENCE_INTERRUPT_COMMAND_ERROR;
#else
  if (trans->use_tty) {
    if (trans->eof_sent) {
      twopence_log_error("Cannot send Ctrl-C, channel already closed for writing\n");
      return TWOPENCE_INTERRUPT_COMMAND_ERROR;
    }

    if (ssh_channel_write(channel, "\003", 1) != 1)
      return TWOPENCE_INTERRUPT_COMMAND_ERROR;
  } else {
    twopence_debug("Command not being run in tty, just shutting it down\n");
  }
  __twopence_ssh_fake_exit_signal(trans, SIGINT);
#endif

  /* When we catch a signal, ssh_event_dopoll will return SSH_ERROR to the
   * caller. Looks like a bug in their code.
   * Nevertheless, work around that by telling __twopence_ssh_poll to ignore
   * that error.
   */
  __twopence_ssh_interrupted = true;
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
  handle = twopence_calloc(1, sizeof(struct twopence_ssh_target));
  if (handle == NULL) return NULL;

  // Store the plugin type
  handle->base.plugin_type = TWOPENCE_PLUGIN_SSH;
  handle->base.ops = &twopence_ssh_ops;

  handle->transactions.next_pid = 1;

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

  handle->event = ssh_event_new();

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

  copy_spec = twopence_strdup(arg);
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

  if (cmd->command == NULL)
    return TWOPENCE_PARAMETER_ERROR;

  /* 'major' makes no sense for SSH and 'minor' defaults to 0 */
  memset(status_ret, 0, sizeof(*status_ret));

  // Execute the command
  return __twopence_ssh_command_ssh(handle, cmd, status_ret);
}

/*
 * Wait for a remote command to finish
 */
static int
twopence_ssh_wait(struct twopence_target *opaque_handle, int want_pid, twopence_status_t *status)
{
  struct twopence_ssh_target *handle = (struct twopence_ssh_target *) opaque_handle;
  twopence_ssh_transaction_t *trans = NULL;
  int rc;

  twopence_debug2("%s(pid=%d)", __func__, want_pid);
  while (true) {
    trans = __twopence_ssh_get_completed_transaction(handle, want_pid);
    if (trans != NULL)
      break;

    if (!handle->transactions.running)
      break;

    rc = __twopence_ssh_poll(handle);
    if (rc < 0)
      return rc;

    if (!__twopence_ssh_reap_completed(handle))
      return TWOPENCE_INTERNAL_ERROR;
  }

  if (trans == NULL)
    return 0;

  assert(trans->done);

  if (trans->exception < 0) {
    rc = trans->exception;
  } else {
    *status = trans->status;
    rc = trans->pid;
  }

  __twopence_ssh_transaction_free(trans);
  return rc;
}

static int
twopence_ssh_chat_send(twopence_target_t *opaque_handle, int pid, twopence_iostream_t *stream)
{
  struct twopence_ssh_target *handle = (struct twopence_ssh_target *) opaque_handle;
  twopence_ssh_transaction_t *trans = NULL;

  trans = __twopence_ssh_transaction_by_pid(handle, pid);
  if (trans == NULL)
    return TWOPENCE_INVALID_TRANSACTION;

  __twopence_ssh_transaction_detach_stdin(trans);
  __twopence_ssh_transaction_setup_stdin(trans, stream, false);

  /* Push data to server */
  if (trans->stdin.fd < 0 && !trans->stdin.eof) {
    if (__twopence_ssh_transaction_drain_stdin(trans) < 0)
      return -1;
  }

  return 0;
}

static int
twopence_ssh_chat_recv(twopence_target_t *opaque_handle, int pid, const struct timeval *deadline)
{
  struct twopence_ssh_target *handle = (struct twopence_ssh_target *) opaque_handle;
  twopence_ssh_transaction_t *trans = NULL;
  int rc;

  trans = __twopence_ssh_transaction_by_pid(handle, pid);
  if (trans == NULL)
    return TWOPENCE_INVALID_TRANSACTION;

  /* The caller may have added some more data to the write buffer. Drain it now */
  if (trans->stdin.fd < 0 && !trans->stdin.eof) {
    if (__twopence_ssh_transaction_drain_stdin(trans) < 0)
      return -1;
  }

  trans->chat.nreceived = 0;
  while (!trans->done && !trans->chat.nreceived && !trans->eof_seen) {
    /* Note, deadline may be NULL; in this case, we time out when
     * the command times out. */
    trans->chat.timeout = deadline;

    /* This flag tells __twopence_ssh_poll to return as soon as we've
     * received new data on the command's stdout */
    trans->chat.waiting = true;

    rc = __twopence_ssh_poll(handle);

    trans->chat.waiting = false;
    trans->chat.timeout = NULL;

    if (rc < 0)
      return rc;

    (void) __twopence_ssh_reap_completed(handle);
  }

  return trans->chat.nreceived;
}

// Inject a file into the remote host
//
// Returns 0 if everything went fine
static int
twopence_ssh_inject_file(struct twopence_target *opaque_handle,
		twopence_file_xfer_t *xfer, twopence_status_t *status)
{
  struct twopence_ssh_target *handle = (struct twopence_ssh_target *) opaque_handle;
  twopence_scp_transaction_t state;
  char *dirname, *basename;
  long filesize;
  int rc;

  // Connect to the remote host
  twopence_scp_transfer_init(&state, handle);
  if ((rc = twopence_scp_transfer_open_session(&state, xfer->user)) < 0)
    return rc;

  if (xfer->print_dots)
    twopence_scp_transfer_print_dots(&state);

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
    rc = __twopence_ssh_inject_ssh(&state, &tmp_xfer, dirname, basename, status);
    twopence_iostream_free(tmp_xfer.local_stream);
  } else {
    rc = __twopence_ssh_inject_ssh(&state, xfer, dirname, basename, status);
  }

  if (rc == 0 && (status->major != 0 || status->minor != 0))
    rc = TWOPENCE_REMOTE_FILE_ERROR;

  /* Destroy all state, and disconnect from remote host */
  twopence_scp_transfer_destroy(&state);

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
  twopence_scp_transaction_t state;
  int rc;

  // Connect to the remote host
  twopence_scp_transfer_init(&state, handle);
  if ((rc = twopence_scp_transfer_open_session(&state, xfer->user)) < 0)
    return rc;

  if (xfer->print_dots)
    twopence_scp_transfer_print_dots(&state);

  // Extract the file
  rc = __twopence_ssh_extract_ssh(&state, xfer, status);
  if (rc == 0 && (status->major != 0 || status->minor != 0))
    rc = TWOPENCE_REMOTE_FILE_ERROR;

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

// Disconnect from remote, and cancel all pending transactions
//
// Returns 0 if everything went fine
static int
twopence_ssh_disconnect(struct twopence_target *opaque_handle)
{
  struct twopence_ssh_target *handle = (struct twopence_ssh_target *) opaque_handle;

  __twopence_ssh_cancel_transactions(handle, TWOPENCE_TRANSPORT_ERROR);

  /* We could also mark the handle in a way to make future
   * command executions etc fail, just for symmetry with the
   * pipe targets.
   * But I currently don't see the point of doing that. */
  return 0;
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

  ssh_event_free(handle->event);

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
	.wait = twopence_ssh_wait,
	.chat_recv = twopence_ssh_chat_recv,
	.chat_send = twopence_ssh_chat_send,
	.inject_file = twopence_ssh_inject_file,
	.extract_file = twopence_ssh_extract_file,
	.exit_remote = twopence_ssh_exit_remote,
	.interrupt_command = twopence_ssh_interrupt_command,
	.disconnect = twopence_ssh_disconnect,
	.end = twopence_ssh_end,
};
