/*
Just the utility routines for Twopence.


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
#include <string.h>
#include <malloc.h>
#include <dlfcn.h>

#include "../library/twopence.h"

// Parse the target string to determine which plugin to use
// Returns 0 = virtio
//         1 = ssh
//         2 = serial
//        -1 = unknown
int target_plugin(const char *target)
{
  const char *end;

  // Get position of ':'
  for (end = target; *end; end++)
    if (*end == ':') break;
  if (end == target || *end == '\0') return -1;

  // Compare with known plugins
  if (!strncmp(target, "virtio", end - target))
    return 0;
  if (!strncmp(target, "ssh", end - target))
    return 1;
  if (!strncmp(target, "serial", end - target))
    return 2;
  return -1;
}

// Parse the target string to get the name of a file
// (it could be a virtio socket or a serial port)
// The result is allocated with malloc() and must be freed by the caller
char *target_virtio_serial_filename(const char *target)
{
  const char *begin, *end;
  char *result;
  int len;

  // Get position after ':'
  for (begin = target; *begin; begin++)
    if (*begin == ':') break;
  if (*begin != '\0')
    begin++;

  // Get position of final NUL
  for (end = begin; *end; end++)
    ;

  // Allocate the result
  len = end - begin;
  result = (char *) malloc(len + 1);

  // Copy the filename to the result
  if (result)
    strcpy(result, begin);

  return result;
}

// Parse the target string to get an IP address or domain name
// The result is allocated with malloc() and must be freed by the caller
char *target_ssh_hostname(const char *target)
{
  const char *begin, *end;
  bool brackets;                     // IPv6 square brackets notation, for example '[::1]'
  char *result;
  int len;

  // Get position after ':'
  for (begin = target; *begin; begin++)
    if (*begin == ':') break;
  if (*begin == ':') begin++;
  brackets = *begin == '[';
  if (brackets) begin++;

  // Get position of final NUL, end bracket, or port number colon
  for (end = begin; *end; end++)
  {
    if (*end == ':' && !brackets)
      break;
    if (*end == ']' && brackets)
      break;
  }

  // Allocate the result
  len = end - begin;
  result = (char *) malloc(len + 1);

  // Copy the filename to the result
  if (result)
  {
    strncpy(result, begin, len);
    result[len] = '\0';
  }

  return result;
}

// Parse the target string to get a port number
// Returns the port number or -1 in case of error
int target_ssh_port(const char *target)
{
  const char *begin, *end;
  int port, rank;

  // Get position of final NUL
  // Also get position of last colon
  begin = target - 1;
  for (end = target;
       *end;
       end++) if (*end == ':') begin = end;

  // Analyze backwards the port number
  port = 0; rank = 1;
  for (--end; end > begin; end--)
  {
     if (*end == ':')
       break;
     if (*end < '0' || '9' < *end)
       break;
     port += rank * (*end - '0');
     rank *= 10;
  }
  if (end < target)                    // Target string made only of digits, makes no sense, handled only for safety
    return -1;
  if (*end != ':')                     // Other hostnames, return default SSH port
    return 22;
  return port;                         // A colon, then a series of digits, it looks like a port number
}

// Open a plugin library given by its filename
void *open_library(const char *filename)
{
  void *dl_handle = dlopen(filename, RTLD_LAZY); 

  if (dl_handle == NULL)
    fprintf(stderr, "Cannot open shared library \"%s\"\n", filename);

  return dl_handle;
}

// Get a symbol from the DLL
void *get_function(void *dl_handle, const char *symbol)
{
  void *function = dlsym(dl_handle, symbol);

  if (function == NULL)
    fprintf(stderr, "Cannot find function \"%s\", in library\n", symbol);

  return function;
}

// Print an error message according to the twopence error code
// Returns a utility error code
//         -1: parameter error
//         -6: error during the execution of request
//         -8: unknown error
int print_error(int rc)
{
  switch (rc)
  {
    case TWOPENCE_PARAMETER_ERROR:
      fprintf(stderr, "Invalid command parameter.\n");
      return -1;
    case TWOPENCE_OPEN_SESSION_ERROR:
      fprintf(stderr, "Error opening the communication with the system under test.\n");
      return -6;
    case TWOPENCE_SEND_COMMAND_ERROR:
      fprintf(stderr, "Error sending command to the system under test.\n");
      return -6;
    case TWOPENCE_FORWARD_INPUT_ERROR:
      fprintf(stderr, "Error forwarding keyboard input.\n");
      return -6;
    case TWOPENCE_RECEIVE_RESULTS_ERROR:
      fprintf(stderr, "Error receiving the results of action.\n");
      return -6;
    case TWOPENCE_LOCAL_FILE_ERROR:
      fprintf(stderr, "Local error while transferring file.\n");
      return -6;
    case TWOPENCE_SEND_FILE_ERROR:
      fprintf(stderr, "Error sending file to the system under test.\n");
      return -6;
    case TWOPENCE_REMOTE_FILE_ERROR:
      fprintf(stderr, "Remote error while transferring file.\n");
      return -6;
    case TWOPENCE_RECEIVE_FILE_ERROR:
      fprintf(stderr, "Error receiving file from the system under test.\n");
      return -6;
  }
  fprintf(stderr, "Unknow error\n");
  return -8;
}
