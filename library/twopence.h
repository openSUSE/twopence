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
#include "buffer.h"

struct pollfd;

/* API versioning. These values correspond directly to the
 * shared library version numbers */
#define TWOPENCE_API_MAJOR_VERSION	0
#define TWOPENCE_API_MINOR_VERSION	3

// Error codes
#define TWOPENCE_PARAMETER_ERROR             -1
#define TWOPENCE_OPEN_SESSION_ERROR          -2
#define TWOPENCE_SEND_COMMAND_ERROR          -3
#define TWOPENCE_FORWARD_INPUT_ERROR         -4
#define TWOPENCE_RECEIVE_RESULTS_ERROR       -5
#define TWOPENCE_COMMAND_TIMEOUT_ERROR       -6
#define TWOPENCE_LOCAL_FILE_ERROR            -7
#define TWOPENCE_SEND_FILE_ERROR             -8
#define TWOPENCE_REMOTE_FILE_ERROR           -9
#define TWOPENCE_RECEIVE_FILE_ERROR         -10
#define TWOPENCE_INTERRUPT_COMMAND_ERROR    -11
#define TWOPENCE_INVALID_TARGET_ERROR       -12
#define TWOPENCE_UNKNOWN_PLUGIN_ERROR       -13
#define TWOPENCE_INCOMPATIBLE_PLUGIN_ERROR  -14
#define TWOPENCE_UNSUPPORTED_FUNCTION_ERROR -15
#define TWOPENCE_PROTOCOL_ERROR             -16

struct twopence_target;

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
struct twopence_command;
typedef struct twopence_iostream twopence_iostream_t;
typedef struct twopence_file_xfer twopence_file_xfer_t;

struct twopence_plugin {
	const char *		name;

	struct twopence_target *(*init)(const char *);
	int			(*run_test)(struct twopence_target *, struct twopence_command *, twopence_status_t *);

	int			(*inject_file)(struct twopence_target *, twopence_file_xfer_t *, twopence_status_t *);
	int			(*extract_file)(struct twopence_target *, twopence_file_xfer_t *, twopence_status_t *);
	int			(*exit_remote)(struct twopence_target *);
	int			(*interrupt_command)(struct twopence_target *);
	void			(*end)(struct twopence_target *);
};

enum {
	TWOPENCE_PLUGIN_UNKNOWN = -1,
	TWOPENCE_PLUGIN_VIRTIO = 0,
	TWOPENCE_PLUGIN_SSH = 1,
	TWOPENCE_PLUGIN_SERIAL = 2,

	__TWOPENCE_PLUGIN_MAX
};

extern const struct twopence_plugin twopence_ssh_ops;
extern const struct twopence_plugin twopence_virtio_ops;
extern const struct twopence_plugin twopence_serial_ops;

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
#define TWOPENCE_SINK_CHAIN_INIT	{ .eof = false, .count = 0 }

typedef struct twopence_io_ops twopence_io_ops_t;
struct twopence_io_ops {
	void			(*close)(twopence_substream_t *);
	int			(*write)(twopence_substream_t *, const void *, size_t);
	int			(*read)(twopence_substream_t *, void *, size_t);
	int			(*set_blocking)(twopence_substream_t *, bool);
	int			(*poll)(twopence_substream_t *, struct pollfd *, int);
	long			(*filesize)(twopence_substream_t *);
};

struct twopence_substream {
	const twopence_io_ops_t *ops;
	union {
	    void *		data;
	    struct {
	        int		fd;
		bool		close;
	    };
	};
};

typedef struct twopence_command twopence_command_t;
struct twopence_command {
	/* For now, we specify the command as a single string.
	 * It would have been nicer to be able to pass the argv,
	 * but the protocol doesn't support this yet. --okir
	 *
	 * I don't think it would be nicer, for example Cheetah
	 * (https://github.com/openSUSE/cheetah/blob/master/README.md)
	 * has you pass individual arguments, and from a
	 * practical point of view, I find it tedious.
	 * Example: Cheetah.run("ls", "-la", :stdout => stdout)
	 * In pennyworth, they did efforts to make it
	 * a single string again :-) . --ebischoff
	 */
	const char *		command;

	/* The user to run this as. Default to root */
	const char *		user;

	/* The duration in seconds after which we abort the command. Default to 60L */
	long			timeout;

	/* Execute the command in a tty rather than just connected to a pipe.
	 * May be needed for some commands to behave properly */
	bool			request_tty;

	/* FIXME: support passing environment variables to the command --okir
	 *
         * For the time being we can start "bash" as a command
	 *  and pass the environment variables that way,
	 *  but I agree it is suboptimal, putting on TODO. --ebischoff
	 */

	/* How to handle the command's standard I/O.
	 * stdin defaults to no input, stdout and stderr default to
	 * the standard output fds
	 */
	twopence_iostream_t	iostream[__TWOPENCE_IO_MAX];

	twopence_buf_t	buffer[__TWOPENCE_IO_MAX];
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

/*
 * The target type
 */
struct twopence_target {
	unsigned int		plugin_type;

	/* Data related to current command */
	struct {
	    twopence_iostream_t *io;
	} current;

	const struct twopence_plugin *ops;
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
 * Run the specified command and wait for it to complete.
 *
 * The @command parameter points to a struct specifying the command itself,
 * the user to run it as (defaults to root), which timeout (defaults to 60),
 * what file to pass it on standard input, and how to handle its output
 */
extern int		twopence_run_test(struct twopence_target *, twopence_command_t *, twopence_status_t *);

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
extern twopence_buf_t *twopence_command_alloc_buffer(twopence_command_t *, twopence_iofd_t, size_t);
extern void		twopence_command_ostreams_reset(twopence_command_t *);
extern void		twopence_command_ostream_reset(twopence_command_t *, twopence_iofd_t);
extern void		twopence_command_ostream_capture(twopence_command_t *, twopence_iofd_t, twopence_buf_t *);
extern void		twopence_command_iostream_redirect(twopence_command_t *, twopence_iofd_t, int, bool closeit);

/*
 * Utilitiy functions for the xfer struct
 */
extern void		twopence_file_xfer_init(twopence_file_xfer_t *xfer);
extern void		twopence_file_xfer_destroy(twopence_file_xfer_t *xfer);

/*
 * Output handling functions
 */
extern twopence_iostream_t *twopence_target_stream(struct twopence_target *, twopence_iofd_t);
extern int		twopence_target_set_blocking(struct twopence_target *, twopence_iofd_t, bool);
extern int		twopence_target_putc(struct twopence_target *, twopence_iofd_t, char);
extern int		twopence_target_write(struct twopence_target *, twopence_iofd_t, const char *, size_t);

extern int		twopence_iostream_open_file(const char *filename, twopence_iostream_t **ret);
extern int		twopence_iostream_create_file(const char *filename, unsigned int permissions, twopence_iostream_t **ret);
extern int		twopence_iostream_wrap_fd(int fd, bool closeit, twopence_iostream_t **ret);
extern int		twopence_iostream_wrap_buffer(twopence_buf_t *bp, twopence_iostream_t **ret);
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

extern twopence_substream_t *twopence_substream_new_buffer(twopence_buf_t *);
extern twopence_substream_t *twopence_substream_new_fd(int fd, bool closeit);
extern void		twopence_substream_close(twopence_substream_t *);


/*
 * Handling twopence config information
 */
typedef struct twopence_config twopence_config_t;
typedef struct twopence_target_config twopence_target_config_t;

extern twopence_config_t *		twopence_config_new(void);
extern void				twopence_config_free(twopence_config_t *);
extern int				twopence_config_write(twopence_config_t *cfg, const char *path);
extern twopence_config_t *		twopence_config_read(const char *path);
extern twopence_target_config_t *	twopence_config_get_target(twopence_config_t *cfg, const char *name);
extern twopence_target_config_t *	twopence_config_add_target(twopence_config_t *cfg, const char *name, const char *spec);
extern void				twopence_config_set_attr(twopence_config_t *cfg, const char *name, const char *value);
extern const char *			twopence_config_get_attr(twopence_config_t *cfg, const char *name);
extern const char *			twopence_target_config_get_spec(twopence_target_config_t *cfg);
extern void				twopence_target_config_set_attr(twopence_target_config_t *tgt, const char *name, const char *value);
extern const char *			twopence_target_config_get_attr(twopence_target_config_t *tgt, const char *name);
extern const char **			twopence_target_config_attr_names(const twopence_target_config_t *);


#endif /* TWOPENCE_H */
