/*
File extraction command. It is used to retrieve a file from some testing environment.
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

#include "../util/util.h"

char *short_options = "u:h";
struct option long_options[] = {
  { "user", 1, NULL, 'u' },
  { "help", 0, NULL, 'h' },
  { NULL, 0, NULL, 0 }
};

// Display a message about the command usage
void usage(const char *program_name)
{
    fprintf(stderr, "Usage: %s [<options>] <target> <remote file> <local file>\n\
Options: -u|--user <user>: user extracting the file (default: root)\n\
         -h|--help: print this help message\n\
Target: serial:<character device>\n\
        ssh:<address and port>\n\
        virtio:<socket file>\n", program_name);
}

// Example syntax for virtio plugin:
//   twopence_extract -u johndoe virtio:/tmp/sut.sock remote_file.txt local_file.txt
//
//   it will use /tmp/sut.sock
//   to communicate with the QEmu/KVM host.
//
// Example syntax for ssh plugin:
//   ./twopence_extract --user=johndoe ssh:host.example.com remote_file.txt local_file.txt
//
//   it is functionally equivalent to
//   "scp johndoe@host.example.com:remote_file.txt local_file.txt",
//   so it is not very interesting when used from the shell...
//
// Example syntax for serial plugin:
//   ./twopence_extract serial:/dev/ttyS0 remote_file.txt local_file.txt
int main(int argc, char *argv[])
{
  int option;
  const char *opt_user,
             *opt_target, *opt_remote, *opt_local;
  struct twopence_target *target;
  int rc, remote_error;

  // Parse options
  opt_user = NULL;
  while ((option = getopt_long(argc, argv, short_options, long_options, NULL))
         != -1) switch(option)         // parse individual options
  {
    case 'u': opt_user = optarg;
              break;
    case 'h': usage(argv[0]);
              exit(0);
    default: usage(argv[0]);
             exit(-1);
  }
  if (opt_user == NULL)                // default user
    opt_user = "root";
  if (argc != optind + 3)              // mandatory arguments: target, remote and local
  {
    usage(argv[0]);
    exit(-1);
  }
  opt_target = argv[optind++];
  opt_remote = argv[optind++];
  opt_local = argv[optind++];

  rc = twopence_target_new(opt_target, &target);
  if (rc < 0) {
    twopence_perror("Error while initializing library", rc);
    exit(1);
  }

  // Extract file
  rc = twopence_extract_file(target, opt_user, opt_remote, opt_local,
                       &remote_error, true);
  if (rc == 0) {
    printf("File successfully extracted\n");
  } else {
    twopence_perror("Unable to extract file", rc);
  }
  if (remote_error != 0)
    fprintf(stderr, "Remote error code: %d\n", remote_error);

  // End library
  twopence_target_free(target);
  return rc;
}
