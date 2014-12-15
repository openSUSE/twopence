/*
Test library. It is used to send tests to a system under test (SUT).


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

#ifndef TWOPENCE_H
#define TWOPENCE_H

#include <stdbool.h>

/* API versioning. These values correspond directly to the
 * shared library version numbers */
#define TWOPENCE_API_MAJOR_VERSION	0
#define TWOPENCE_API_MINOR_VERSION	2

// Error codes
#define TWOPENCE_PARAMETER_ERROR -1
#define TWOPENCE_OPEN_SESSION_ERROR -2
#define TWOPENCE_SEND_COMMAND_ERROR -3
#define TWOPENCE_FORWARD_INPUT_ERROR -4
#define TWOPENCE_RECEIVE_RESULTS_ERROR -5
#define TWOPENCE_LOCAL_FILE_ERROR -6
#define TWOPENCE_SEND_FILE_ERROR -7
#define TWOPENCE_REMOTE_FILE_ERROR -8
#define TWOPENCE_RECEIVE_FILE_ERROR -9
#define TWOPENCE_INTERRUPT_COMMAND_ERROR -10
#define TWOPENCE_INVALID_TARGET_SPEC -11
#define TWOPENCE_UNKNOWN_PLUGIN -12
#define TWOPENCE_INCOMPATIBLE_PLUGIN -13
#define TWOPENCE_NOT_SUPPORTED -14
#define TWOPENCE_PROTOCOL_ERROR -15

struct twopence_target;

typedef int (*twopence_test_t1)(struct twopence_target *, const char *, const char *, int *, int *);
typedef int (*twopence_test_t2)(struct twopence_target *, const char *, const char *, char *, int, int *, int *);
typedef int (*twopence_test_t3)(struct twopence_target *, const char *, const char *, char *, char *, int, int *, int *);
typedef int (*twopence_inject_t)(struct twopence_target *, const char *, const char *, const char *, int *, bool);
typedef int (*twopence_extract_t)(struct twopence_target *, const char *, const char *, const char *, int *, bool);
typedef int (*twopence_exit_t)(struct twopence_target *);
typedef int (*twopence_interrupt_t)(struct twopence_target *);
typedef void (*twopence_end_t)(struct twopence_target *);

struct twopence_plugin {
	const char *		name;

	struct twopence_target *(*init)(const char *);
	twopence_test_t1	test_and_print_results;
	twopence_test_t1	test_and_drop_results;
	twopence_test_t2	test_and_store_results_together;
	twopence_test_t3	test_and_store_results_separately;
	twopence_inject_t	inject_file;
	twopence_extract_t	extract_file;
	twopence_exit_t		exit_remote;
	twopence_interrupt_t	interrupt_command;
	twopence_end_t		end;
};

enum {
	TWOPENCE_PLUGIN_UNKNOWN = -1,
	TWOPENCE_PLUGIN_VIRTIO = 0,
	TWOPENCE_PLUGIN_SSH = 1,
	TWOPENCE_PLUGIN_SERIAL = 2,

	__TWOPENCE_PLUGIN_MAX
};

/*
 * Output related data types.
 * At some point, we probably want to support concurrent execution of several
 * commands, at which point we'll have to make these per-command.
 */
typedef enum {
	TWOPENCE_OUTPUT_NONE,
	TWOPENCE_OUTPUT_SCREEN,
	TWOPENCE_OUTPUT_BUFFER,
	TWOPENCE_OUTPUT_BUFFER_SEPARATELY,
} twopence_output_t;

struct twopence_buffer {
	char *		tail;
	char *		end;
};

struct twopence_sink {
	twopence_output_t mode;
	struct twopence_buffer outbuf;
	struct twopence_buffer errbuf;
};

/*
 * The target type
 */
struct twopence_target {
	unsigned int		plugin_type;

	/* Data related to current command */
	struct {
		struct twopence_sink	sink;
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
					const char *username, const char *command,
					int *major_ret, int *minor_ret);

/*
 * Run a test command, and drop all output
 *
 * Arguments and results like twopence_test_and_print_results() above
 */
extern int		twopence_test_and_drop_results(struct twopence_target *target,
					const char *username, const char *command,
					int *major_ret, int *minor_ret);

/*
 * Run a test command, and store the results in memory in a common buffer
 *
 * Input:
 *   handle: the handle returned by the initialization function
 *   username: the user's name inside of the SUT
 *   command: the Linux command to run inside of the SUT
 *   buffer: the buffer where the standard output and standard error of the command should go
 *   size: the common size of both buffers
 *   major: the return code of the test server
 *   minor: the return code of the command
 *
 * Output:
 *   0 if everything went fine, otherwise a twopence error code.
 */
extern int		twopence_test_and_store_results_together(struct twopence_target *target,
					const char *username, const char *command,
					char *buffer, int size,
					int *major_ret, int *minor_ret);

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
					const char *username, const char *command,
					char *stdout_buffer, char *stderr_buffer, int size,
					int *major_ret, int *minor_ret);

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
 * Output handling functions
 */
extern void		twopence_sink_init(struct twopence_sink *, twopence_output_t, char *, char *, size_t);
extern void		twopence_sink_init_none(struct twopence_sink *);
extern int		twopence_sink_putc(struct twopence_sink *sink, bool is_error, char c);
extern int		twopence_sink_write(struct twopence_sink *sink, bool is_error, const char *data, size_t len);

/* These should really go to a private header file, as they're internal to the plugins */
extern int		__twopence_sink_write_stderr(struct twopence_sink *sink, char c);
extern int		__twopence_sink_write_stdout(struct twopence_sink *sink, char c);

extern int		twopence_tune_stdin(bool blocking);

#endif /* TWOPENCE_H */
