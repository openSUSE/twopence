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

struct twopence_target;

// Initialize the virtio library
//
// Input:
//   filename: the filename of an UNIX domain socket
//
// Output:
//   A "handle" that must be passed to subsequent function calls,
//   or NULL in case of a problem.
//
// Example:
//   twopence_init_virtio_t twopence_init;
//   handle = (*twopence_init)
//              (filename);
typedef struct twopence_target *(*twopence_init_virtio_t)(const char *);

// Initialize the ssh library
//
// Input:
//   hostname: an IP address or a domain name
//   port: a port number
//
// Output:
//   A "handle" that must be passed to subsequent function calls,
//   or NULL in case of a problem.
//
// Example:
//   twopence_init_ssh_t twopence_init;
//   handle = (*twopence_init)
//              (hostname, port);
typedef struct twopence_target *(*twopence_init_ssh_t)(const char *, unsigned int);

// Initialize the serial library
//
// Input:
//   filename: the filename of a UNIX character device
//
// Output:
//   A "handle" that must be passed to subsequent function calls,
//   or NULL in case of a problem.
//
// Example:
//   twopence_init_serial_t twopence_init;
//   handle = (*twopence_init)
//              (filename);
typedef struct twopence_target *(*twopence_init_serial_t)(const char *);

// Run a test command, and print or drop output
//
// Input:
//   handle: the handle returned by the initialization function
//   username: the user's name inside of the SUT
//   command: the Linux command to run inside of the SUT
//   major: the return code of the test server
//   minor: the return code of the command
//
// Output:
//   0 if everything went fine.
//
// Examples:
//   twopence_test_t1 twopence_test_and_print_results;
//   rc = (*twopence_test_and_print_results)
//          (handle, username, command, &major, &minor);
//
//   twopence_test_t1 twopence_test_and_drop_results;
//   rc = (*twopence_test_and_drop_results)
//          (handle, username, command, &major, &minor);
typedef int (*twopence_test_t1)(struct twopence_target *, const char *, const char *, int *, int *);

// Run a test command, and store the results in memory in a common buffer
//
// Input:
//   handle: the handle returned by the initialization function
//   username: the user's name inside of the SUT
//   command: the Linux command to run inside of the SUT
//   buffer: the buffer where the standard output and standard error of the command should go
//   size: the common size of both buffers
//   major: the return code of the test server
//   minor: the return code of the command
//
// Output:
//   0 if everything went fine.
//
// Example:
//   twopence_test_t2 twopence_test_and_store_results_together;
//   rc = (*twopence_test_and_store_results_together)
//          (handle, username, command, buffer, size, &major, &minor);
typedef int (*twopence_test_t2)(struct twopence_target *, const char *, const char *, char *, int, int *, int *);

// Run a test command, and store the results in memory in two separate buffers
//
// Input:
//   handle: the handle returned by the initialization function
//   username: the user's name inside of the SUT
//   command: the Linux command to run inside of the SUT
//   buffer_out: the buffer where the standard output of the command should go
//   buffer_err: the buffer where the standard output of the command should go
//   size: the common size of both buffers
//   major: the return code of the test server
//   minor: the return code of the command
//
// Output:
//   0 if everything went fine.
//
// Example:
//  twopence_test_t3 twopence_test_and_store_results_separately;
//  rc = (*twopence_test_and_store_results_separately)
//         (handle, username, command, buffer_out, buffer_err, size, &major, &minor);
typedef int (*twopence_test_t3)(struct twopence_target *, const char *, const char *, char *, char *, int, int *, int *);

// Inject a file into the system under test
//
// Input:
//   handle: the handle returned by the initialization function
//   username: the user's name inside of the SUT
//   local_filename: the name of the local file to send
//   remote_filename: the name of the file inside of the SUT
//   remote_rc: the return code of the test server
//   dots: 'true' if we want to display progress dots
//
// Output:
//   0 if everything went fine.
//
// Example:
//   twopence_inject_t twopence_inject_file;
//   rc = (*twopence_inject_file)
//          (handle, username, local_filename, remote_filename, &remote_rc, false);
typedef int (*twopence_inject_t)(struct twopence_target *, const char *, const char *, const char *, int *, bool);

// Extract a file from the system under test
//
// Input:
//   handle: the handle returned by the initialization function
//   username: the user's name inside of the SUT
//   remote_filename: the name of the file inside of the SUT
//   local_filename: the name of the local file to send
//   remote_rc: the return code of the test server
//   dots: 'true' if we want to display progress dots
//
// Output:
//   0 if everything went fine.
//
// Example:
//   twopence_extract_t twopence_extract_file;
//   rc = (*twopence_extract_file)
//          (handle, username, remote_filename, local_filename, &remote_rc, false);
typedef int (*twopence_extract_t)(struct twopence_target *, const char *, const char *, const char *, int *, bool);

// Tell the remote test server to exit
// WARNING: you won't be able to run further tests after that,
//          unless you restart the test server
//
// Input:
//   handle: the handle returned by the initialization function
//
// Output:
//   Returns 0 if everything went fine.
//
// Example:
//   twopence_exit_t twopence_exit_remote;
//   rc = (*twopence_exit_remote)
//          (handle);
typedef int (*twopence_exit_t)(struct twopence_target *);

// Interrupt current command
//
// Input:
//   handle: the handle returned by the initialization function
//
// Output:
//   Returns 0 if everything went fine.
//
// Example:
//   twopence_interrupt_t twopence_interrupt_command;
//   (*twopence_interrupt_command)
//          (handle);
typedef int (*twopence_interrupt_t)(struct twopence_target *);

// Close the library
//
// Input:
//   handle: the handle returned by the initialization function
//
// Output:
//   (none)
//
// Example:
//   twopence_end_t twopence_end;
//   (*twopence_end)(handle);
typedef void (*twopence_end_t)(struct twopence_target *);

struct twopence_plugin {
	const char *		name;

	twopence_test_t1	test_and_print_results;
	twopence_test_t1	test_and_drop_results;
	twopence_test_t2	test_and_store_results_together;
	twopence_test_t3	test_and_store_results_separately;
	twopence_inject_t	inject_file;
	twopence_extract_t	extract_file;
	twopence_exit_t		exit_remote;
	twopence_interrupt_t	interrupt_command;
};

enum {
	TWOPENCE_PLUGIN_UNKNOWN = -1,
	TWOPENCE_PLUGIN_VIRTIO = 0,
	TWOPENCE_PLUGIN_SSH = 1,
	TWOPENCE_PLUGIN_SERIAL = 2,
};

struct twopence_target {
	unsigned int		plugin_type;
	const struct twopence_plugin *ops;
};

#endif /* TWOPENCE_H */
