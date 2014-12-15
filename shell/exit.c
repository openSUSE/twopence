/*
Exit command. It is used to stop the testing environment.
Currently the only supported environment is a livirt virtual machine.

WARNING: after that, you won't be able to run any more tests,
         unless you restart the test server


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

#include "../util/util.h"

// Display a message about the command usage
void usage(const char *program_name)
{
    fprintf(stderr, "Usage: %s <target>\n\
Target: serial:<character device>\n\
        ssh:<address and port>\n\
        virtio:<socket file>\n", program_name);
}

// Example syntax for virtio plugin:
//   ./twopence_exit virtio:/tmp/sut.sock
//
//   it will use /tmp/sut.sock
//   to communicate with the QEmu/KVM host.
//
// Example syntax for serial plugin:
//   ./twopence_exit serial:/dev/ttyS0
//
// Main program
int main(int argc, const char *argv[])
{
  struct twopence_target *target;
  int rc;

  // Check arguments
  if (argc != 2)
  {
    usage(argv[0]);
    exit(-1);
  }

  rc = twopence_target_new(argv[1], &target);
  if (rc < 0) {
    fprintf(stderr, "Error while initializing library\n");
    print_error(rc);
    exit(1);
  }

  // Let the remote test server exit
  rc = target->ops->exit_remote(target);
  if (rc == 0)
    printf("Asked the test server to exit.\n");
  else
    rc = print_error(rc);

  // End library
  twopence_target_free(target);
  return rc;
}
