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

#include "../util/util.h"

char buffer[65536];
twopence_interrupt_t interrupt_command;
void *twopence_handle;

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

// Get the hostname and the port
int get_hostname_and_port
  (char **hostname, unsigned int *port, const char *target)
{
  char *h;
  int p;

  h = target_ssh_hostname(target);
  if (h == NULL)
  {
    return -1;
  }

  p = target_ssh_port(target);
  if (p < 0 || p > 65535)
  {
    free(h);
    return -1;
  }

  *hostname = h;
  *port = (unsigned int) p;
  return 0;
}

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
  (*interrupt_command)                 // return code is ignored
    (twopence_handle);
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
  void *dl_handle;
  int target_type;
  void *init_library;                  // either twopence_init_virtio_t or twopence_init_ssh_t
  twopence_test_t1 test_command1;
  twopence_test_t1 test_command2;
  twopence_test_t2 test_command3;
  twopence_test_t3 test_command4;
  twopence_end_t end_library;
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

  // Load library
  target_type = target_plugin(opt_target);
  switch (target_type)
  {
    case 0:                            // virtio
      dl_handle = open_library("libtwopence_virtio.so.0");
      break;
    case 1:                            // ssh
      dl_handle = open_library("libtwopence_ssh.so.0");
      break;
    case 2:                            // serial
      dl_handle = open_library("libtwopence_serial.so.0");
      break;
    default:                           // unknown
      fprintf(stderr, "Unknown target: %s\n", opt_target);
      exit(-1);
  }
  if (dl_handle == NULL) exit(-2);

  // Get symbols
  init_library = get_function(dl_handle, "twopence_init");
  test_command1 = get_function(dl_handle, "twopence_test_and_print_results");
  test_command2 = get_function(dl_handle, "twopence_test_and_drop_results");
  test_command3 = get_function(dl_handle, "twopence_test_and_store_results_together");
  test_command4 = get_function(dl_handle, "twopence_test_and_store_results_separately");
  interrupt_command = get_function(dl_handle, "twopence_interrupt_command");
  end_library = get_function(dl_handle, "twopence_end");

  // Check symbols
  if (init_library == NULL ||
      test_command1 == NULL ||
      test_command2 == NULL ||
      test_command3 == NULL ||
      test_command4 == NULL ||
      interrupt_command == NULL ||
      end_library == NULL)
  {
    dlclose(dl_handle);
    exit(-3);
  }

  // Init library
  switch (target_type)
  {
    case 0:                            // virtio
      {
        char *socketname;

        socketname = target_virtio_serial_filename(opt_target);

        if (socketname == NULL)
        {
          dlclose(dl_handle);
          exit(-1);
        }

        twopence_handle = (*(twopence_init_virtio_t) init_library)
                            (socketname);
        free(socketname);
      }
      break;
    case 1:                            // ssh
      {
        char *hostname;
        unsigned int port;

        if (get_hostname_and_port(&hostname, &port, opt_target) < 0)
        {
          dlclose(dl_handle);
          exit(-1);
        }

        twopence_handle = (*(twopence_init_ssh_t) init_library)
                            (hostname, port);
        free(hostname);
      }
      break;
    case 2:                            // serial
      {
        char *devicename;

        devicename = target_virtio_serial_filename(opt_target);

        if (devicename == NULL)
        {
          dlclose(dl_handle);
          exit(-1);
        }

        twopence_handle = (*(twopence_init_serial_t) init_library)
                            (devicename);
        free(devicename);
      }
      break;
  }
  if (twopence_handle == NULL)
  {
    fprintf(stderr, "Error while initializing library\n");
    dlclose(dl_handle);
    exit(-4);
  }

  // Install signal handler
  if (install_handler(SIGINT, &old_action))
  {
    fprintf(stderr, "Error installing signal handler\n");
    (*end_library)(twopence_handle);
    dlclose(dl_handle);
    exit(-5);
  }

  // Run command
  switch (opt_type)
  {
    case 1:
      rc = (*test_command1)(twopence_handle, opt_user, opt_command,
                            &major, &minor);
      break;
    case 2:
      rc = (*test_command2)(twopence_handle, opt_user, opt_command,
                            &major, &minor);
      break;
    case 3:
      rc = (*test_command3)(twopence_handle, opt_user, opt_command,
                            buffer, 65536, &major, &minor);
      break;
    case 4:
      rc = (*test_command4)(twopence_handle, opt_user, opt_command,
                            buffer, buffer + 32768, 32768, &major, &minor);
  }
  if (rc == 0)
  {
    if (!opt_batch)
    {
      printf("Return code from the test server: %d\n", major);
      printf("Return code of tested command: %d\n", minor);
    }
    if (major || minor) rc = -7;
  }
  else rc = print_error(rc);

  // Restore original signal handler
  if (restore_handler(SIGINT, &old_action))
  {
    fprintf(stderr, "Error removing signal handler\n");
    (*end_library)(twopence_handle);
    dlclose(dl_handle);
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
  (*end_library)(twopence_handle);
  dlclose(dl_handle);
  return rc;
}
