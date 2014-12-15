/*
Test command. It is used to send a test command to some testing environment.
Currently the only supported environment is a livirt virtual machine.


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

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>

#include "twopence.h"

char buffer[65536];
struct twopence_target *twopence_handle;

char *short_options = "u:o:1:2:qbh";
struct option long_options[] = {
  { "user", 1, NULL, 'u' },
  { "output", 1, NULL, 'o' },
  { "stdout", 1, NULL, '1' },
  { "stderr", 1, NULL, '2' },
  { "quiet", 0, NULL, 'q' },
  { "batch", 0, NULL, 'b' },
  { "help", 0, NULL, 'h' },
  { NULL, 0, NULL, 0 }
};

void signal_handler(int signum)
{
  static bool interrupt_in_progress = false;

  if (interrupt_in_progress)
  {
    printf("OK, exiting immediately.");
    exit(-7);
  }
  printf("\nInterrupted.\n");
  interrupt_in_progress = true;
  twopence_interrupt_command(twopence_handle);
  interrupt_in_progress = false;
}

int install_handler(int signum, struct sigaction *old_action)
{
  struct sigaction new_action;

  new_action.sa_handler = signal_handler;
  sigemptyset(&new_action.sa_mask);
  new_action.sa_flags = 0;

  return sigaction(signum, &new_action, old_action);
}

int restore_handler(int signum, const struct sigaction *old_action)
{
  return sigaction(signum, old_action, NULL);
}

// Write output to file, in case we were requested not to ouput it to screen
int write_output(const char *filename, const char *buf)
{
  FILE *fp;

  fp = fopen(filename, "wb");
  if (fp == NULL)
  {
    fprintf(stderr, "Error while opening output file \"%s\"\n", filename);
    return -6;
  }
  if (fputs(buf, fp) < 0)
  {
    fprintf(stderr, "Error while writing output to file \"%s\"\n", filename);
    return -6;
  }
  if (fclose(fp) < 0)
  {
    fprintf(stderr, "Error closing output file \"%s\"\n", filename);
    return -6;
  }
  return 0;
}

// Display a message about the command usage
void usage(const char *program_name)
{
    fprintf(stderr, "Usage: %s [<options>] <target> <command>\n\
Options: -u|--user <user>: user running the command (default: root)\n\
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
  const char *opt_user, *opt_output, *opt_stdout, *opt_stderr;
  bool opt_quiet, opt_batch;
  int opt_type;
  const char *opt_target, *opt_command;
  struct twopence_target *target;
  struct sigaction old_action;
  int major, minor, rc, rc2;

  // Parse options
  opt_user = NULL;
  opt_output = NULL; opt_stdout = NULL; opt_stderr = NULL;
  opt_quiet = false; opt_batch = false;
  while ((option = getopt_long(argc, argv, short_options, long_options, NULL))
         != -1) switch(option)         // parse individual options
  {
    case 'u': opt_user = optarg;
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
              exit(0);
    default: usage(argv[0]);
             exit(-1);
  }
  if (opt_user == NULL)                // default user
    opt_user = "root";
  if (opt_output == NULL &&            // output specifiers
      opt_stdout == NULL && opt_stderr == NULL)
    opt_type = opt_quiet? 2: 1;
  else if (opt_quiet == false &&
           opt_output != NULL &&
           opt_stdout == NULL && opt_stderr == NULL)
    opt_type = 3;
  else if (opt_quiet == false &&
           opt_output == NULL &&
           opt_stdout != NULL && opt_stderr != NULL)
    opt_type = 4;
  else
  {
    usage(argv[0]);
    exit(-1);
  }
  if (argc != optind + 2)              // mandatory arguments: target and command
  {
    usage(argv[0]);
    exit(-1);
  }
  opt_target = argv[optind++];
  opt_command = argv[optind++];

  rc = twopence_target_new(opt_target, &target);
  if (rc < 0) {
    twopence_perror("Error while initializing library", rc);
    exit(1);
  }

  // Install signal handler
  twopence_handle = target;
  if (install_handler(SIGINT, &old_action)) {
    fprintf(stderr, "Error installing signal handler\n");
    twopence_target_free(target);
    exit(-5);
  }

  // Run command
  switch (opt_type)
  {
    case 1:
      rc = twopence_test_and_print_results(target, opt_user, opt_command,
                            &major, &minor);
      break;
    case 2:
      rc = twopence_test_and_drop_results(target, opt_user, opt_command,
                            &major, &minor);
      break;
    case 3:
      rc = twopence_test_and_store_results_together(target, opt_user, opt_command,
                            buffer, 65536, &major, &minor);
      break;
    case 4:
      rc = twopence_test_and_store_results_separately(target, opt_user, opt_command,
                            buffer, buffer + 32768, 32768, &major, &minor);
  }

  if (rc == 0) {
    if (!opt_batch) {
      printf("Return code from the test server: %d\n", major);
      printf("Return code of tested command: %d\n", minor);
    }
    if (major || minor) rc = -7;
  } else {
    twopence_perror("Unable to execute command", rc);
  }

  // Restore original signal handler
  if (restore_handler(SIGINT, &old_action))
  {
    fprintf(stderr, "Error removing signal handler\n");
    twopence_target_free(target);
    if (rc == 0) rc = -5;
  }

  // Write captured stdout and stderr to 0, 1, or 2 files
  switch (opt_type)
  {
    case 3:
      rc2 = write_output(opt_output, buffer);
      if (rc == 0) rc = rc2;
      break;
    case 4:
      rc2 = write_output(opt_stdout, buffer);
      if (rc == 0) rc = rc2;
      rc2 = write_output(opt_stderr, buffer + 32768);
      if (rc == 0) rc = rc2;
  }

  // End library
  twopence_target_free(target);
  return rc;
}
