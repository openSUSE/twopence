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
  void *dl_handle;
  int target_type;
  void *init_library; // either twopence_init_virtio_t or twopence_init_ssh_t
  twopence_extract_t extract_file;
  twopence_end_t end_library;
  void *twopence_handle;
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

  // Load library
  target_type = target_plugin(opt_target);
  switch (target_type)
  {
    case 0: // virtio
      dl_handle = open_library("libtwopence_virtio.so.0");
      break;
    case 1: // ssh
      dl_handle = open_library("libtwopence_ssh.so.0");
      break;
    case 2:                            // serial
      dl_handle = open_library("libtwopence_serial.so.0");
      break;
    default: // unknown
      fprintf(stderr, "Unknown target: %s\n", opt_target);
      exit(-1);
  }
  if (dl_handle == NULL) exit(-2);

  // Get symbols
  init_library = get_function(dl_handle, "twopence_init");
  extract_file = get_function(dl_handle, "twopence_extract_file");
  end_library = get_function(dl_handle, "twopence_end");

  // Check symbols
  if (init_library == NULL ||
      extract_file == NULL ||
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

  // Extract file
  rc = (*extract_file)(twopence_handle, opt_user, opt_remote, opt_local,
                       &remote_error, true);
  if (rc == 0) printf("File successfully extracted\n");
  else rc = print_error(rc);
  if (remote_error != 0)
    fprintf(stderr, "Remote error code: %d\n", remote_error);

  // End library
  (*end_library)(twopence_handle);
  dlclose(dl_handle);
  return rc;
}
