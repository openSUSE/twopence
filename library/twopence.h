/*
Test library. It is used to send tests to a system under test (SUT).


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

#ifndef TWOPENCE_H
#define TWOPENCE_H

#include <stdbool.h>
#include <stdio.h>
#include <sys/time.h>
#include "buffer.h"

struct pollfd;

/* API versioning. These values correspond directly to the
 * shared library version numbers */
#define TWOPENCE_API_MAJOR_VERSION	0
#define TWOPENCE_API_MINOR_VERSION	3

/* Error codes */
#define TWOPENCE_PARAMETER_ERROR		-1
#define TWOPENCE_OPEN_SESSION_ERROR		-2
#define TWOPENCE_SEND_COMMAND_ERROR		-3
#define TWOPENCE_FORWARD_INPUT_ERROR		-4
#define TWOPENCE_RECEIVE_RESULTS_ERROR		-5
#define TWOPENCE_COMMAND_TIMEOUT_ERROR		-6
#define TWOPENCE_LOCAL_FILE_ERROR		-7
#define TWOPENCE_SEND_FILE_ERROR		-8
#define TWOPENCE_REMOTE_FILE_ERROR		-9
#define TWOPENCE_RECEIVE_FILE_ERROR		-10
#define TWOPENCE_INTERRUPT_COMMAND_ERROR	-11
#define TWOPENCE_INVALID_TARGET_ERROR		-12
#define TWOPENCE_UNKNOWN_PLUGIN_ERROR		-13
#define TWOPENCE_INCOMPATIBLE_PLUGIN_ERROR	-14
#define TWOPENCE_UNSUPPORTED_FUNCTION_ERROR	-15
#define TWOPENCE_PROTOCOL_ERROR			-16
#define TWOPENCE_INTERNAL_ERROR			-17
#define TWOPENCE_TRANSPORT_ERROR		-18
#define TWOPENCE_INCOMPATIBLE_PROTOCOL_ERROR	-19
#define TWOPENCE_INVALID_TRANSACTION		-20

typedef struct twopence_target twopence_target_t;

/*
 * Executing commands on the SUT always returns two status words -
 * major:	this is the status of the twopence test server,
 *		indicating any issues encountered while executing
 *		the command.
 * minor:	this is the exit status of the command itself.
 *
 * FIXME: we should dissect the status code on the SUT rather than
 * the system running twopence, as the exit code, signal information
 * etc is architecture dependent.
 *
 * FIXME2: we should probably rename these members to something like
 * plugin_code and exit_code.
 */
typedef struct twopence_status {
	int			major;
	int			minor;
} twopence_status_t;

/* Forward decls for the plugin functions */
typedef struct twopence_command twopence_command_t;
typedef struct twopence_iostream twopence_iostream_t;
typedef struct twopence_file_xfer twopence_file_xfer_t;
typedef struct twopence_chat twopence_chat_t;
typedef struct twopence_expect twopence_expect_t;
typedef struct twopence_timer twopence_timer_t;

struct twopence_plugin {
	const char *		name;

	struct twopence_target *(*init)(const char *);
	int			(*set_option)(struct twopence_target *, int, const void *);

	int			(*run_test)(struct twopence_target *, struct twopence_command *, twopence_status_t *);
	int			(*wait)(struct twopence_target *, int, twopence_status_t *);
	int			(*chat_recv)(twopence_target_t *, int, const struct timeval *);
	int			(*chat_send)(twopence_target_t *, int, twopence_iostream_t *);

	int			(*inject_file)(struct twopence_target *, twopence_file_xfer_t *, twopence_status_t *);
	int			(*extract_file)(struct twopence_target *, twopence_file_xfer_t *, twopence_status_t *);
	int			(*exit_remote)(struct twopence_target *);
	int			(*interrupt_command)(struct twopence_target *);
	int			(*disconnect)(twopence_target_t *);
	void			(*end)(struct twopence_target *);
};

enum {
	TWOPENCE_PLUGIN_UNKNOWN = -1,
	TWOPENCE_PLUGIN_VIRTIO = 0,
	TWOPENCE_PLUGIN_SSH = 1,
	TWOPENCE_PLUGIN_SERIAL = 2,
	TWOPENCE_PLUGIN_TCP = 3,
	TWOPENCE_PLUGIN_CHROOT = 4,
	TWOPENCE_PLUGIN_LOCAL = 5,

	__TWOPENCE_PLUGIN_MAX
};

extern const struct twopence_plugin twopence_ssh_ops;
extern const struct twopence_plugin twopence_virtio_ops;
extern const struct twopence_plugin twopence_serial_ops;
extern const struct twopence_plugin twopence_tcp_ops;
extern const struct twopence_plugin twopence_chroot_ops;
extern const struct twopence_plugin twopence_local_ops;

/*
 * Output related data types.
 * At some point, we probably want to support concurrent execution of several
 * commands, at which point we'll have to make these per-command.
 */
typedef enum {
	TWOPENCE_STDIN = 0,
	TWOPENCE_STDOUT = 1,
	TWOPENCE_STDERR = 2,

	__TWOPENCE_IO_MAX
} twopence_iofd_t;

typedef struct twopence_substream twopence_substream_t;


#define TWOPENCE_IOSTREAM_MAX_SUBSTREAMS	4
struct twopence_iostream {
	bool			eof;
	unsigned int		count;
	twopence_substream_t *	substream[TWOPENCE_IOSTREAM_MAX_SUBSTREAMS];
};

typedef struct twopence_env {
	unsigned int		count;
	char **			array;
} twopence_env_t;

struct twopence_command {
	/* Specify the command as a single string.
	 * This gets passed to /bin/sh on the remote end, so wildcards,
	 * shell expansion etc is fully supported.
	 */
	const char *		command;

	/* The user to run this as. Default to root */
	const char *		user;

	/* The duration in seconds after which we abort the command. Default to 60L */
	long			timeout;

	/* Execute the command in a tty rather than just connected to a pipe.
	 * May be needed for some commands to behave properly */
	bool			request_tty;

	/* Do not wait for the command to finish, but execute it in
	 * the background.
	 */
	bool			background;

	/* Do not propagate local EOF of stdin to remote command.
	 * This is needed for chat scripting
	 */
	bool			keepopen_stdin;

	/* This is the set of environment variables being
	 * passed from the client to the server.
	 */
	twopence_env_t		env;

	/* How to handle the command's standard I/O.
	 * stdin defaults to no input, stdout and stderr default to
	 * the standard output fds
	 */
	twopence_iostream_t	iostream[__TWOPENCE_IO_MAX];

	twopence_buf_t		buffer[__TWOPENCE_IO_MAX];
};

typedef struct twopence_remote_file twopence_remote_file_t;
struct twopence_remote_file {
	const char *		name;
	unsigned int		mode;
};

struct twopence_file_xfer {
	twopence_iostream_t *	local_stream;
	twopence_remote_file_t	remote;

	/* remote user account to use for this transfer.
	 * If NULL, defaults to root */
	const char *		user;

	/* if true, print dots for every chunk of data transferred */
	bool			print_dots;
};

struct twopence_chat {
	int			pid;

	twopence_buf_t *	recvbuf;
	twopence_buf_t *	sendbuf;
	twopence_iostream_t *	stdin;

	/* When chat_recv returns, this buffer contains the
	 * data we skipped over, including the string we
	 * were waiting for. */
	twopence_buf_t		consumed;

	/* When chat_recv returns, this contains the
	 * string we matched.
	 */
	char *			found;
};

#define TWOPENCE_EXPECT_MAX_STRINGS	16
struct twopence_expect {
	unsigned int		timeout;

	unsigned int		nstrings;
	const char *		strings[TWOPENCE_EXPECT_MAX_STRINGS];
};

/*
 * Timer objects
 */
enum {
	TWOPENCE_TIMER_STATE_ACTIVE,
	TWOPENCE_TIMER_STATE_PAUSED,
	TWOPENCE_TIMER_STATE_EXPIRED,
	TWOPENCE_TIMER_STATE_CANCELLED,
	TWOPENCE_TIMER_STATE_DEAD,
};

struct twopence_timer {
	struct twopence_timer **prev;
	struct twopence_timer *	next;

	unsigned int		refcount;

	unsigned int		id;
	unsigned int		connection_id;

	int			state;
	struct timeval		runtime;
	struct timeval		expires;

	/* This callback is invoked when the timer expired.
	 */
	void			(*callback)(twopence_timer_t *, void *user_data);
	void *			user_data;
};

/*
 * The target type
 */
struct twopence_target {
	unsigned int		plugin_type;

	const struct twopence_plugin *ops;

	/* This is the default environment that is
	 * being passed to the server on all
	 * remote command executions. */
	twopence_env_t		env;
};

/*
 * Create a target for the given plugin
 *
 * Input:
 *   A plugin-specific argument.
 *   serial:   full path name of the serial device to use
 *   virtio:   full path name of the AF_LOCAL socket to connect to
 *   ssh:      the target hostname, optionally followed by ":portname"
 *             When using numeric IPv6 addresses, make sure to include
 *             the address in [] brackets, as in [::1]
 *
 * Output:
 *   A "handle" that must be passed to subsequent function calls,
 *   or NULL in case of a problem.
 */
extern int		twopence_target_new(const char *target_spec, struct twopence_target **ret);

/*
 * Set target-specific options
 *
 * Currently, the only use we have for this is to tune the keepalive
 * values; and the only reason we want to do this is to test keepalive :-)
 * Not sure whether this warrant a first-class interface, but I had
 * no better idea.
 */
extern int		twopence_target_set_option(struct twopence_target *,
					int option, const void *value_p);

enum {
	TWOPENCE_TARGET_OPTION_KEEPALIVE = 0,	/* value_p is an int pointer */
};

/*
 * Set default environment variables passed to each command executed
 */
extern void		twopence_target_setenv(twopence_target_t *target,
					const char *name, const char *value);

/*
 * Specify environment variables to be passed from the applications
 * environment to each command being executed.
 * This is equivalent to calling
 *   twopence_target_setenv(target, name, getenv(name));
 */
extern void		twopence_target_passenv(twopence_target_t *target,
					const char *name);

/*
 * Run the specified command and wait for it to complete.
 *
 * The @command parameter points to a struct specifying the command itself,
 * the user to run it as (defaults to root), which timeout (defaults to 60),
 * what file to pass it on standard input, and how to handle its output
 *
 * If the backend supports it, you can run commands in the background by setting
 * command->background = true.
 * This will assign a "pid" to the command, which will be returned.
 */
extern int		twopence_run_test(struct twopence_target *, twopence_command_t *, twopence_status_t *);

/*
 * Wait for a previously backgrounded command to complete.
 *
 * Returns:
 *  < 0:	an error occured
 *  0:		no more processes
 * either an error (negative) or the "pid" of the completed process.
 */
extern int		twopence_wait(struct twopence_target *, int, twopence_status_t *);

/*
 * Initialize a chat object
 */
extern void		twopence_chat_init(twopence_chat_t *chat, twopence_buf_t *, twopence_buf_t *);

/*
 * Destroy a chat object
 */
extern void		twopence_chat_destroy(twopence_chat_t *chat);

/*
 * Run the specified command and set it up for chat scripting.
 *
 * This requires backgrounding support.
 */
extern int		twopence_chat_begin(twopence_target_t *, twopence_command_t *cmd, twopence_chat_t *chat);

/*
 * Wait for the command to output the expected string.
 *
 * If the string is received, remove all data up to and including the string from the
 * local receive buffer, and return the number of bytes consumed.
 *
 * If timeout is non-negative, wait for at most the specified number of seconds before giving up.
 * In case of a timeout, a COMMAND_TIMEOUT error is returned.
 * If @timeout is negative, the overall command timeout applies.
 *
 * If the command exited, or closed its output channels, without having printed the expected
 * string, this function will return 0.
 *
 * In case of any errors, the (negative) error code will be returned.
 */
extern int		twopence_chat_expect(twopence_target_t *, twopence_chat_t *chat, const twopence_expect_t *args);

/*
 * Send the given string to the command's standard input
 */
extern void		twopence_chat_puts(twopence_target_t *, twopence_chat_t *chat, const char *string);

/*
 * Read one line of text from the remote command's output.
 * If no full line is found in the receive buffer, wait for a complete line for up to @timeout seconds.
 * If @timeout is negative, the overall command timeout applies.
 */
extern char *		twopence_chat_gets(twopence_target_t *, twopence_chat_t *chat, char *buf, size_t size, int timeout);

/*
 * Run a test command, and print output
 *
 * Input:
 *   handle: the handle returned by the initialization function
 *   username: the user's name inside of the SUT
 *   command: the Linux command to run inside of the SUT
 *   major: the return code of the test server
 *   minor: the return code of the command
 *
 * Output:
 *   0 if everything went fine, otherwise a twopence error code.
 */
extern int		twopence_test_and_print_results(struct twopence_target *target,
					const char *username, long timeout, const char *command,
					twopence_status_t *status);

/*
 * Run a test command, and drop all output
 *
 * Arguments and results like twopence_test_and_print_results() above
 */
extern int		twopence_test_and_drop_results(struct twopence_target *target,
					const char *username, long timeout, const char *command,
					twopence_status_t *status);

/*
 * Run a test command, and store the results in memory in a common buffer
 *
 * Input:
 *   handle: the handle returned by the initialization function
 *   username: the user's name inside of the SUT
 *   command: the Linux command to run inside of the SUT
 *   buffer: the buffer where the standard output and standard error of the command should go
 *   major: the return code of the test server
 *   minor: the return code of the command
 *
 * Output:
 *   0 if everything went fine, otherwise a twopence error code.
 */
extern int		twopence_test_and_store_results_together(struct twopence_target *target,
					const char *username, long timeout, const char *command,
					twopence_buf_t *buffer,
					twopence_status_t *status);

/*
 * Run a test command, and store the results in memory in two separate buffers
 *
 * Input:
 *   handle: the handle returned by the initialization function
 *   username: the user's name inside of the SUT
 *   command: the Linux command to run inside of the SUT
 *   buffer_out: the buffer where the standard output of the command should go
 *   buffer_err: the buffer where the standard output of the command should go
 *   size: the common size of both buffers
 *   major: the return code of the test server
 *   minor: the return code of the command
 *
 * Output:
 *   0 if everything went fine, otherwise a twopence error code.
 */
extern int		twopence_test_and_store_results_separately(struct twopence_target *target,
					const char *username, long timeout, const char *command,
					twopence_buf_t *stdout_buffer, twopence_buf_t *stderr_buffer,
					twopence_status_t *status);

/*
 * Inject a file into the system under test
 *
 * Input:
 *   handle: the handle returned by the initialization function
 *   username: the user's name inside of the SUT
 *   local_filename: the name of the local file to send
 *   remote_filename: the name of the file inside of the SUT
 *   remote_rc: the return code of the test server
 *   dots: 'true' if we want to display progress dots
 *
 * Output:
 *   0 if everything went fine, otherwise a twopence error code.
 */
extern int		twopence_inject_file(struct twopence_target *target,
					const char *username, const char *local_path, const char *remote_path,
					int *remote_rc, bool blabla);

extern int		twopence_send_file(struct twopence_target *target,
					twopence_file_xfer_t *xfer, twopence_status_t *status);

/*
 * Extract a file from the system under test
 *
 * Input:
 *   handle: the handle returned by the initialization function
 *   username: the user's name inside of the SUT
 *   remote_filename: the name of the file inside of the SUT
 *   local_filename: the name of the local file to send
 *   remote_rc: the return code of the test server
 *   dots: 'true' if we want to display progress dots
 *
 * Output:
 *   0 if everything went fine, otherwise a twopence error code.
 */
extern int		twopence_extract_file(struct twopence_target *target,
					const char *username, const char *remote_path, const char *local_path,
					int *remote_rc, bool blabla);

extern int		twopence_recv_file(struct twopence_target *target,
					twopence_file_xfer_t *xfer, twopence_status_t *status);

/*
 * Tell the remote test server to exit
 * WARNING: you won't be able to run further tests after that,
 *          unless you restart the test server
 *
 * Input:
 *   handle: the handle returned by the initialization function
 *
 * Output:
 *   Returns 0 if everything went fine.
 */
extern int		twopence_exit_remote(struct twopence_target *target);

/*
 * Disconnect from the SUT, and cancel all pending transactions.
 *
 * It will be possible to reap the status of pending commands
 * after this, but all attempts to interact with the remote
 * system will return TWOPENCE_TRANSPORT_ERROR.
 *
 * Input:
 *   handle: the handle returned by the initialization function
 *
 * Output:
 *   Returns 0 if everything went fine.
 */
extern int		twopence_disconnect(twopence_target_t *target);

/*
 * Interrupt current command
 *
 * Input:
 *   handle: the handle returned by the initialization function
 *
 * Output:
 *   Returns 0 if everything went fine.
 *
 * Example:
 */
extern int		twopence_interrupt_command(struct twopence_target *target);


/*
 * Create a global timer.
 */
extern int		twopence_timer_create(unsigned long timeout_ms, twopence_timer_t **timer_ret);

/*
 * Close the library
 *
 * Input:
 *   handle: the handle returned by the initialization function
 *
 * Output:
 *   (none)
 */
extern void		twopence_target_free(struct twopence_target *target);

extern const char *	twopence_strerror(int rc);
extern void		twopence_perror(const char *, int rc);

/*
 * Handling for the command struct
 */
extern void		twopence_command_init(twopence_command_t *cmd, const char *cmdline);
extern void		twopence_command_destroy(twopence_command_t *cmd);
extern void		twopence_command_setenv(twopence_command_t *cmd, const char *name, const char *value);
extern void		twopence_command_passenv(twopence_command_t *cmd, const char *name);
extern void		twopence_command_merge_default_env(twopence_command_t *cmd, const twopence_env_t *def_env);
extern twopence_buf_t *	twopence_command_alloc_buffer(twopence_command_t *, twopence_iofd_t, size_t);
extern void		twopence_command_ostreams_reset(twopence_command_t *);
extern void		twopence_command_ostream_reset(twopence_command_t *, twopence_iofd_t);
extern void		twopence_command_ostream_capture(twopence_command_t *, twopence_iofd_t, twopence_buf_t *);
extern void		twopence_command_iostream_redirect(twopence_command_t *, twopence_iofd_t, int, bool closeit);

extern void		twopence_env_init(twopence_env_t *env);
extern void		twopence_env_set(twopence_env_t *, const char *name, const char *value);
extern void		twopence_env_unset(twopence_env_t *, const char *name);
extern void		twopence_env_pass(twopence_env_t *, const char *name);
extern void		twopence_env_copy(twopence_env_t *env, const twopence_env_t *src_env);
extern void		twopence_env_merge_inferior(twopence_env_t *env, const twopence_env_t *def_env);
extern void		twopence_env_destroy(twopence_env_t *);

/*
 * Utilitiy functions for the xfer struct
 */
extern void		twopence_file_xfer_init(twopence_file_xfer_t *xfer);
extern void		twopence_file_xfer_destroy(twopence_file_xfer_t *xfer);

/*
 * Output handling functions
 */
extern int		twopence_iostream_open_file(const char *filename, twopence_iostream_t **ret);
extern int		twopence_iostream_create_file(const char *filename, unsigned int permissions, twopence_iostream_t **ret);
extern int		twopence_iostream_wrap_fd(int fd, bool closeit, twopence_iostream_t **ret);
extern int		twopence_iostream_wrap_buffer(twopence_buf_t *bp, bool resizable, twopence_iostream_t **ret);
extern void		twopence_iostream_free(twopence_iostream_t *);
extern void		twopence_iostream_add_substream(twopence_iostream_t *, twopence_substream_t *);
extern void		twopence_iostream_destroy(twopence_iostream_t *);
extern bool		twopence_iostream_eof(const twopence_iostream_t *);
extern int		twopence_iostream_putc(twopence_iostream_t *, char);
extern int		twopence_iostream_write(twopence_iostream_t *, const char *, size_t);
extern int		twopence_iostream_getc(twopence_iostream_t *);
extern int		twopence_iostream_read(twopence_iostream_t *, char *, size_t);
extern twopence_buf_t *	twopence_iostream_read_all(twopence_iostream_t *);
extern int		twopence_iostream_set_blocking(twopence_iostream_t *, bool);
extern int		twopence_iostream_poll(twopence_iostream_t *, struct pollfd *, int mask);
extern long		twopence_iostream_filesize(twopence_iostream_t *);
extern int		twopence_iostream_getfd(twopence_iostream_t *);

extern twopence_substream_t *twopence_substream_new_buffer(twopence_buf_t *, bool resizable);
extern twopence_substream_t *twopence_substream_new_fd(int fd, bool closeit);
extern void		twopence_substream_close(twopence_substream_t *);

/*
 * Timer functions
 */
extern void		twopence_timer_set_callback(twopence_timer_t *, void (*callback)(twopence_timer_t *, void *), void *);
extern void		twopence_timer_hold(twopence_timer_t *);
extern void		twopence_timer_release(twopence_timer_t *);
extern void		twopence_timer_cancel(twopence_timer_t *);
extern void		twopence_timer_pause(twopence_timer_t *);
extern void		twopence_timer_unpause(twopence_timer_t *);
extern long		twopence_timer_remaining(const twopence_timer_t *);

/*
 * Logging functions
 */
extern void		twopence_logging_init();
extern void		twopence_set_logfile(FILE *fp);
extern void		twopence_set_syslog(bool on);
extern void		twopence_trace(const char *fmt, ...);
extern void		twopence_log_error(const char *fmt, ...);
extern void		twopence_log_warning(const char *fmt, ...);

extern unsigned int	twopence_debug_level;

#define __twopence_debug(level, fmt...) \
			do { \
				if (twopence_debug_level >= level) \
					twopence_trace(fmt); \
			} while (0)
#define twopence_debug(fmt...)   __twopence_debug(1, fmt)
#define twopence_debug2(fmt...)  __twopence_debug(2, fmt)

#endif /* TWOPENCE_H */
