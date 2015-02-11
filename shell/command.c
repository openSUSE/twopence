/*
Test command. It is used to send a test command to some testing environment.
Currently the only supported environment is a livirt virtual machine.


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

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>

#include "shell.h"
#include "twopence.h"

struct twopence_target *twopence_handle;

char *short_options = "u:t:o:1:2:qbh";
struct option long_options[] = {
  { "user", 1, NULL, 'u' },
  { "timeout", 1, NULL, 't' },
  { "output", 1, NULL, 'o' },
  { "stdout", 1, NULL, '1' },
  { "stderr", 1, NULL, '2' },
  { "quiet", 0, NULL, 'q' },
  { "batch", 0, NULL, 'b' },
  { "help", 0, NULL, 'h' },
  { NULL, 0, NULL, 0 }
};

// Handle interrupt
void signal_handler(int signum)
{
  static bool interrupt_in_progress = false;

  if (interrupt_in_progress)
  {
    printf("OK, exiting immediately.");
    exit(RC_ABORTED_BY_USER);
  }
  printf("\nInterrupted.\n");
  interrupt_in_progress = true;
  twopence_interrupt_command           // return code is ignored
    (twopence_handle);
  interrupt_in_progress = false;
}

// Install interrupt handler
//
// Returns 0 on success, -1 on error
int install_handler(int signum, struct sigaction *old_action)
{
  struct sigaction new_action;

  new_action.sa_handler = signal_handler;
  sigemptyset(&new_action.sa_mask);
  new_action.sa_flags = 0;

  return sigaction(signum, &new_action, old_action);
}

// Restore old interrupt handler
//
// Returns 0 on success, -1 on error
int restore_handler(int signum, const struct sigaction *old_action)
{
  return sigaction(signum, old_action, NULL);
}

// Write output to file, in case we were requested not to ouput it to screen
//
// Returns 0 on success, -1 on error
int write_output(const char *filename, const twopence_buffer_t *bp)
{
  FILE *fp;
  unsigned int count;

  fp = fopen(filename, "wb");
  if (fp == NULL)
  {
    fprintf(stderr, "Error while opening output file \"%s\"\n", filename);
    return -1;
  }

  count = twopence_buf_count(bp);
  fwrite(twopence_buf_head(bp), 1, count, fp);
  if (ferror(fp))
  {
    fprintf(stderr, "Error while writing output to file \"%s\"\n", filename);
    return -1;
  }
  if (fclose(fp) < 0)
  {
    fprintf(stderr, "Error closing output file \"%s\"\n", filename);
    return -1;
  }
  return 0;
}

// Display a message about the command usage
void usage(const char *program_name)
{
    fprintf(stderr, "Usage: %s [<options>] <target> <command>\n\
Options: -u|--user <user>: user running the command (default: root)\n\
         -t|--timeout: time in seconds before aborting the command (default: 60)\n\
         -o|--output <file>: store both the output and the errors in the same file\n\
         -1|--stdout <file1> -2|--stderr <file2>: store them separately\n\
         -q|--quiet: do not display command output nor errors\n\
         -b|--batch: do not display status messages\n\
         -h|--help: print this help message\n\
Target: serial:<character device>\n\
        ssh:<address and port>\n\
        virtio:<socket file>\n\
Command: any UNIX command\n", program_name);
}

// Main program
int main(int argc, char *argv[])
{
  int option;
  const char *opt_output, *opt_stdout, *opt_stderr;
  bool opt_quiet, opt_batch;
  const char *opt_target;

  twopence_command_t cmd;
  struct twopence_target *target;
  struct sigaction old_action;
  twopence_buffer_t stdout_buf, stderr_buf;
  twopence_status_t status;
  int rc;

  // Parse options
  opt_output = NULL; opt_stdout = NULL; opt_stderr = NULL;
  opt_quiet = false; opt_batch = false;

  twopence_command_init(&cmd, NULL);

  while ((option = getopt_long(argc, argv, short_options, long_options, NULL))
         != -1) switch(option)         // parse individual options
  {
    case 'u': cmd.user = optarg;
              break;
    case 't': cmd.timeout = atol(optarg);
              break;
    case 'o': opt_output = optarg;
              break;
    case '1': opt_stdout = optarg;
              break;
    case '2': opt_stderr = optarg;
              break;
    case 'q': opt_quiet = true;
              break;
    case 'b': opt_batch = true;
              break;
    case 'h': usage(argv[0]);
              exit(RC_OK);

    invalid_options:
    default: usage(argv[0]);
             exit(RC_INVALID_PARAMETERS);
  }

  if (argc != optind + 2)              // mandatory arguments: target and command
    goto invalid_options;

  opt_target = argv[optind++];
  cmd.command = argv[optind++];

  twopence_command_ostreams_reset(&cmd);
  twopence_command_iostream_redirect(&cmd, TWOPENCE_STDIN, 0, false);

  twopence_buf_init(&stdout_buf);
  twopence_buf_init(&stderr_buf);

  if (opt_quiet) {
    if (opt_output || opt_stdout || opt_stderr) {
      fprintf(stderr, "You cannot use options -o, -1 or -2 with -q\n");
      goto invalid_options;
    }

    /* Output streams are not connected. */
  } else
  if (opt_output) {
    if (opt_stdout || opt_stderr) {
      fprintf(stderr, "You cannot use options -o together with -1 or -2\n");
      goto invalid_options;
    }
    /* Connect both output streams to the same buffer */
    twopence_buf_resize(&stdout_buf, 65536);
    twopence_command_ostream_capture(&cmd, TWOPENCE_STDOUT, &stdout_buf);
    twopence_command_ostream_capture(&cmd, TWOPENCE_STDERR, &stdout_buf);
  } else
  if (opt_stdout || opt_stderr) {
    /* Connect both output streams to separate buffers */
    twopence_buf_resize(&stdout_buf, 65536);
    twopence_command_ostream_capture(&cmd, TWOPENCE_STDOUT, &stdout_buf);
    twopence_buf_resize(&stderr_buf, 65536);
    twopence_command_ostream_capture(&cmd, TWOPENCE_STDERR, &stderr_buf);
  } else {
    /* No output, no -q option. Just send everything to our regular output. */

    /* FIXME: if our stdout and stderr are redirected to the same file,
     * we should merge the standard output of the command on the server
     * side. */

    twopence_command_iostream_redirect(&cmd, TWOPENCE_STDOUT, 1, false);
    twopence_command_iostream_redirect(&cmd, TWOPENCE_STDERR, 2, false);
  }

  // Create target object
  rc = twopence_target_new(opt_target, &target);
  if (rc < 0)
  {
    twopence_perror("Error while initializing library", rc);
    exit(RC_LIBRARY_INIT_ERROR);
  }

  // Install signal handler
  twopence_handle = target;
  if (install_handler(SIGINT, &old_action))
  {
    fprintf(stderr, "Error installing signal handler\n");
    twopence_target_free(target);
    exit(RC_SIGNAL_HANDLER_ERROR);
  }

  // Run command
  rc = twopence_run_test(twopence_handle, &cmd, &status);

  if (rc == 0)
  {
    if (!opt_batch)
    {
      printf("Return code from the test server: %d\n", status.major);
      printf("Return code of tested command: %d\n", status.minor);
    }
    if (status.major || status.minor)
      rc = RC_REMOTE_COMMAND_FAILED;
  }
  else
  {
    twopence_perror("Unable to execute command", rc);
    rc = RC_EXEC_COMMAND_ERROR;
  }

  // Restore original signal handler
  if (restore_handler(SIGINT, &old_action))
  {
    fprintf(stderr, "Error removing signal handler\n");
    twopence_target_free(target);
    if (rc == 0) rc = RC_SIGNAL_HANDLER_ERROR;
  }

  // Write captured stdout and stderr to 0, 1, or 2 files
  if (opt_output) {
    if (write_output(opt_output, &stdout_buf) < 0)
      if (rc == 0) rc = RC_WRITE_RESULTS_ERROR;
  } else {
    if (opt_stdout)
      if (write_output(opt_stdout, &stdout_buf) < 0)
        if (rc == 0) rc = RC_WRITE_RESULTS_ERROR;
    if (opt_stderr)
      if (write_output(opt_stderr, &stderr_buf) < 0)
        if (rc == 0) rc = RC_WRITE_RESULTS_ERROR;
  }

  // End library
  twopence_target_free(target);
  return rc;
}
