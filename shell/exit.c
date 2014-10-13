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
  void *dl_handle;
  int target_type;
  twopence_init_virtio_t init_library;
  twopence_exit_t exit_remote;
  twopence_end_t end_library;
  void *twopence_handle;
  int rc;

  // Check arguments
  if (argc != 2)
  {
    usage(argv[0]);
    exit(-1);
  }

  // Load library
  target_type = target_plugin(argv[1]);
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
      fprintf(stderr, "Unknown target: %s\n", argv[1]);
      exit(-1);
  }
  if (dl_handle == NULL) exit(-2);

  // Get symbols
  init_library = get_function(dl_handle, "twopence_init");
  exit_remote = get_function(dl_handle, "twopence_exit_remote");
  end_library = get_function(dl_handle, "twopence_end");

  // Check symbols
  if (init_library == NULL ||
      exit_remote == NULL ||
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

        socketname = target_virtio_serial_filename(argv[1]);
        if (socketname == NULL)
        {
          dlclose(dl_handle);
          exit(-1);
        }

        twopence_handle = (*init_library)
                            (socketname);

        free(socketname);
      }
      break;
    case 1:                            // ssh
      fprintf(stderr, "Can't exit the remote test server with the SSH plugin, \
because there's no remote test server\n");
      dlclose(dl_handle);
      exit(-1);
    case 2:                            // serial
      {
        char *devicename;

        devicename = target_virtio_serial_filename(argv[1]);

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

  // Let the remote test server exit
  rc = (*exit_remote)(twopence_handle);
  if (rc == 0)
    printf("Asked the test server to exit.\n");
  else
    rc = print_error(rc);

  // End library
  (*end_library)(twopence_handle);
  dlclose(dl_handle);
  return rc;
}
