/*
Test executor, TCP plugin.

NOTE: Absolutely no authentication with this transport!

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

#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>

#include "twopence.h"
#include "pipe.h"

#define TWOPENCE_TCP_PORT_DEFAULT_STR	"64123"


struct twopence_tcp_target {
  struct twopence_pipe_target pipe;

  char *server_spec;
};

extern const struct twopence_plugin twopence_tcp_ops;
extern const struct twopence_pipe_ops twopence_tcp_link_ops;

///////////////////////////// Lower layer ///////////////////////////////////////

// Initialize the handle
//
// Returns 0 if everything went fine, or -1 in case of error
static int
__twopence_tcp_init(struct twopence_tcp_target *handle, const char *server_spec)
{

  twopence_pipe_target_init(&handle->pipe, TWOPENCE_PLUGIN_TCP, &twopence_tcp_ops, &twopence_tcp_link_ops);
  handle->server_spec = twopence_strdup(server_spec);
  return 0;
}

/*
 * Open the TCP socket
 *
 * Returns the file descriptor if successful, or -1 if failed
 */
static twopence_sock_t *
__twopence_tcp_open(struct twopence_pipe_target *pipe_handle)
{
  struct twopence_tcp_target *handle = (struct twopence_tcp_target *) pipe_handle;
  char *copy, *hostname, *portname = NULL;
  struct addrinfo hints;
  struct addrinfo *ai_list, *ai;
  int socket_fd = -1;
  int res;

  copy = hostname = twopence_strdup(handle->server_spec);
  if (hostname[0] == '[') {
    /* Something like [::1] */
    char *s;

    for (s = ++hostname; *s != ']'; ++s) {
      if (*s == '\0') {
        twopence_log_error("tcp: cannot parse \"%s\"", handle->server_spec);
	free(copy);
        return NULL;
      }
    }
    *s++ = '\0';
    if (*s == ':')
      portname = ++s;
    /* Any other garbage is silently ignored for now */
  } else
  if ((portname = strchr(hostname, ':')) != NULL)
    *portname++ = '\0';

  if (portname == NULL)
    portname = TWOPENCE_TCP_PORT_DEFAULT_STR;

  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  res = getaddrinfo(hostname, portname, &hints, &ai_list);

  free(copy);
  copy = hostname = portname = NULL;

  if (res != 0) {
    twopence_log_error("tcp: cannot resolve \"%s\": %s", handle->server_spec, gai_strerror(res));
    return NULL;
  }

  twopence_debug("trying to open connection to %s", handle->server_spec);
  for (ai = ai_list; ai && socket_fd < 0; ai = ai->ai_next) {
    socket_fd = socket(ai->ai_family, SOCK_STREAM, 0);
    if (socket_fd <= 0)
      break;

    // Open the connection
    if (connect(socket_fd, ai->ai_addr, ai->ai_addrlen) < 0) {
      /* Okay, this address didn't work. Try the next one */
      close(socket_fd);
      socket_fd = -1;
    }
  }

  freeaddrinfo(ai_list);
  if (socket_fd <= 0)
    return NULL;

  /* Note, we do not pass O_NONBLOCK here, but we do set O_CLOEXEC */
  return twopence_sock_new_flags(socket_fd, O_RDWR | O_CLOEXEC);
}

const struct twopence_pipe_ops twopence_tcp_link_ops = {
  .open = __twopence_tcp_open,
};

///////////////////////////// Public interface //////////////////////////////////

// Initialize the library
//
// This specific plugin takes the filename of a UNIX domain socket as argument
//
// Returns a "handle" that must be passed to subsequent function calls,
// or NULL in case of a problem
static struct twopence_target *
twopence_tcp_init(const char *filename)
{
  struct twopence_tcp_target *handle;

  // Allocate the opaque handle
  handle = twopence_calloc(1, sizeof(struct twopence_tcp_target));
  if (handle == NULL)
    return NULL;

  // Initialize the handle
  if (__twopence_tcp_init(handle, filename) < 0) {
    free(handle);
    return NULL;
  }

  return (struct twopence_target *) handle;
};

/*
 * Define the plugin ops vector
 */
const struct twopence_plugin twopence_tcp_ops = {
	.name		= "tcp",

	.init = twopence_tcp_init,
	.set_option = twopence_pipe_set_option,
	.run_test = twopence_pipe_run_test,
	.wait = twopence_pipe_wait,
	.chat_send = twopence_pipe_chat_send,
	.chat_recv = twopence_pipe_chat_recv,
	.inject_file = twopence_pipe_inject_file,
	.extract_file = twopence_pipe_extract_file,
	.exit_remote = twopence_pipe_exit_remote,
	.interrupt_command = twopence_pipe_interrupt_command,
	.cancel_transactions = twopence_pipe_cancel_transactions,
	.disconnect = twopence_pipe_disconnect,
	.end = twopence_pipe_end,
};
