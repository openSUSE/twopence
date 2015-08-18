/*
File injection command. It is used to send a file into some testing environment.
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

#include "shell.h"
#include "twopence.h"

char *short_options = "u:dvh";
struct option long_options[] = {
  { "user", 1, NULL, 'u' },
  { "debug", 0, NULL, 'd' },
  { "version", 0, NULL, 'v' },
  { "help", 0, NULL, 'h' },
  { NULL, 0, NULL, 0 }
};

// Display a message about the command usage
void usage(const char *program_name)
{
    fprintf(stderr, "Usage: %s [<options>] <target> <local file> <remote file>\n\
Options: -u|--user <user>: user injecting the file (default: root)\n\
         -d|--debug: print debugging information\n\
         -v|--version: print version information\n\
         -h|--help: print this help message\n\
Target: serial:<character device>\n\
        ssh:<address and port>\n\
        virtio:<socket file>\n", program_name);
}

// Main program
int main(int argc, char *argv[])
{
  int option;
  const char *opt_user,
             *opt_target, *opt_local, *opt_remote;
  struct twopence_target *target;
  int rc, remote_error;

  // Parse options
  opt_user = NULL;
  while ((option = getopt_long(argc, argv, short_options, long_options, NULL))
         != -1) switch(option)         // parse individual options
  {
    case 'u': opt_user = optarg;
              break;
    case 'd': twopence_debug_level++;
	      break;
    case 'v': printf("%s version 0.3.5\n", argv[0]);
              exit(RC_OK);
    case 'h': usage(argv[0]);
              exit(RC_OK);
    default: usage(argv[0]);
             exit(RC_INVALID_PARAMETERS);
  }
  if (opt_user == NULL)                // default user
    opt_user = "root";
  if (argc != optind + 3)              // mandatory arguments: target, local and remote
  {
    usage(argv[0]);
    exit(RC_INVALID_PARAMETERS);
  }
  opt_target = argv[optind++];
  opt_local = argv[optind++];
  opt_remote = argv[optind++];

  rc = twopence_target_new(opt_target, &target);
  if (rc < 0)
  {
    twopence_perror("Error while initializing library", rc);
    exit(RC_LIBRARY_INIT_ERROR);
  }

  // Inject file
  rc = twopence_inject_file
         (target, opt_user, opt_local, opt_remote,
          &remote_error, true);
  if (rc == 0)
    printf("File successfully injected\n");
  else
  {
    twopence_perror("Unable to inject file", rc);
    rc = RC_EXTRACT_FILE_ERROR;
  }
  if (remote_error != 0)
    fprintf(stderr, "Remote error code: %d\n", remote_error);

  // End library
  twopence_target_free(target);
  return rc;
}
