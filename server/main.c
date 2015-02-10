/*
Test server. It communicates with the outer world using only serial ports.

The idea is to avoid interfering with networks test. This enables to test
even with all network interfaces are shut down.


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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <pwd.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <termios.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>

#include "server.h"

#define TWOPENCE_SERIAL_PORT_DEFAULT	"/dev/virtio-ports/org.opensuse.twopence.0"
#define TWOPENCE_UNIX_PORT_DEFAULT	"/var/run/twopence.sock"

#define TWOPENCE_SERVER_PARAMETER_ERROR -1
#define TWOPENCE_SERVER_SOCKET_ERROR -2
#define TWOPENCE_SERVER_FORK_ERROR -3

static void		service_connection(int);
static void		server_daemonize(void);

FILE *			server_log_file = NULL;
unsigned int		server_tracing = 0;


////////////////////////////////////// Lower layer ///////////////////////////

// Open the serial port
//
// Returns the file descriptor if successful, -1 otherwise.
int open_serial_port(const char *filename)
{
  int serial_fd;
  struct termios tio;

  if (filename == NULL)
    filename = TWOPENCE_SERIAL_PORT_DEFAULT;

  printf("Listening on %s\n", filename);

  // Open the port
  serial_fd = open(filename, O_RDWR | O_NONBLOCK | O_CLOEXEC | O_NOCTTY);
  if (serial_fd <= 0) {
    fprintf(stderr, "Unable to open serial port %s: %m\n", filename);
    return -1;
  }

  // Set up serial line
  if (isatty(serial_fd))
  {
    bzero(&tio, sizeof(struct termios));
    tio.c_cflag = CRTSCTS | CS8 | CLOCAL | CREAD;
    tio.c_iflag = 0;
    tio.c_oflag = 0;
    tio.c_lflag = 0;
    if (cfsetspeed(&tio, B115200) < 0
     || tcsetattr(serial_fd, TCSANOW, &tio) < 0) {
      fprintf(stderr, "Unable to configure serial port %s: %m\n", filename);
      close(serial_fd);
      return -1;
    }
  }

  return serial_fd;
}

/*
 * This is a crude workaround for something that needs a better fix.
 */
void
wait_for_virtio_host(int serial_fd)
{
  struct pollfd pfd;
  int n, nfail = 0, nloop = 0;

  pfd.fd = serial_fd;
  while (true) {
    pfd.events = POLLIN;

    n = poll(&pfd, 1, 500);
    if (n < 0) {
      perror("poll on serial fd");
      if (nfail >= 10) {
	fprintf(stderr, "Giving up.\n");
	exit(1);
      }

      sleep(++nfail);
      continue;
    }

    if (n > 0) {
      /* As long as nothing has connected to the server side,
       * we will see a POLLHUP. */
      if (!(pfd.revents & POLLHUP))
	return;

      if (nloop++ == 0)
        fprintf(stderr, "Waiting for someone to connect to host side socket\n");
      usleep(500000);
    }
  }
}

/*
 * Open the unix port
 *
 * Returns the file descriptor if successful, -1 otherwise.
 */
int open_unix_port(const char *filename)
{
  struct sockaddr_un sun;
  int listen_fd;

  if (filename == NULL)
    filename = TWOPENCE_UNIX_PORT_DEFAULT;

  printf("Listening on %s\n", filename);

  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_LOCAL;
  strcpy(sun.sun_path, filename);

  listen_fd = socket(PF_LOCAL, SOCK_STREAM, 0);
  if (listen_fd < 0) {
    fprintf(stderr, "Unable to open unix socket: %m\n");
    goto failed;
  }

  unlink(filename);

  if (bind(listen_fd, (struct sockaddr *) &sun, sizeof(sun)) < 0) {
    fprintf(stderr, "Unable to bind unix socket to %s: %m\n", filename);
    goto failed;
  }

  chmod(filename, 0777);
  if (listen(listen_fd, 0) < 0) {
    fprintf(stderr, "Unable to listen on unix socket to %s: %m\n", filename);
    goto failed;
  }

  return listen_fd;

failed:
  if (listen_fd >= 0)
    close(listen_fd);
  return -1;
}

int
accept_unix_connection(int listen_fd)
{
  int sock_fd;

  sock_fd = accept(listen_fd, NULL, NULL);
  if (sock_fd < 0) {
    fprintf(stderr, "Failed to accept connection on unix socket to: %m\n");
    return -1;
  }

  return sock_fd;
}

// Main entry point.
int main(int argc, char *argv[])
{
  static struct option long_opts[] = {
    { "one-shot", no_argument, NULL, '1' },
    { "port-serial", required_argument, NULL, 'S' },
    { "port-pty", no_argument, NULL, 'P' },
    { "port-unix", required_argument, NULL, 'U' },
    { "daemon", no_argument, NULL, 'D' },
    { "debug", no_argument, NULL, 'd' },
    { NULL }
  };
  int opt_oneshot = 0;
  const char *opt_port_type = NULL;
  const char *opt_port_path = NULL;
  bool opt_daemon = false;
  int c;

  // Welcome message, check arguments
  printf("Twopence test server version 0.3.0\n");

  /* Initially, debug logging goes to stderr */
  server_log_file = stderr;

  while ((c = getopt_long(argc, argv, "DdPS:U:", long_opts, NULL)) != -1) {
    switch (c) {
    case '1':
      opt_oneshot = 1;
      break;

    case 'd':
      server_tracing++;
      break;

    case 'D':
      opt_daemon = true;
      break;

    case 'S':
      if (opt_port_type) {
        fprintf(stderr, "Conflicting port types specified on command line\n");
	goto usage;
      }

      opt_port_type = "serial";
      opt_port_path = optarg;
      break;

    case 'P':
      if (opt_port_type) {
        fprintf(stderr, "Conflicting port types specified on command line\n");
	goto usage;
      }

      opt_port_type = "pty";
      opt_port_path = optarg;
      break;

    case 'U':
      if (opt_port_type) {
        fprintf(stderr, "Conflicting port types specified on command line\n");
	goto usage;
      }

      opt_port_type = "unix";
      opt_port_path = optarg;
      break;

    default:
    usage:
	fprintf(stderr,
		"Usage:\n"
		"%s <portspec>\n"
		"Where portspec can be one of the following:\n\n"
		"no arguments:\n"
		"    open the default serial port\n"
		"pathname:\n"
		"    open the specified serial port\n"
		"--port-unix path:\n"
		"    create the specified Unix domain socket and listen on it\n"
		"--port-serial path:\n"
		"    open the specified serial port\n"
		"--port-pty:\n"
		"    open a pty master, print the pty slave path on stdout, and background the server process\n"
		"    This is not implemented yet.\n"
		"\n"
		"The default serial port is %s\n"
		, argv[0], TWOPENCE_SERIAL_PORT_DEFAULT);
        exit(TWOPENCE_SERVER_PARAMETER_ERROR);
    }
  }

  if (opt_port_type == NULL) {
    opt_port_type = "serial";
    if (optind < argc)
      opt_port_path = argv[optind++];
  }

  if (optind < argc) {
    fprintf(stderr, "Too many arguments\n");
    goto usage;
  }

  /* Open the port */
  if (!strcmp(opt_port_type, "serial")) {
    int serial_fd;

    do {
      serial_fd = open_serial_port(opt_port_path);
      if (serial_fd < 0)
        exit(TWOPENCE_SERVER_SOCKET_ERROR);

      /* the virtio serial port will return POLLHUP for as long
       * as nothing has connected to the host side socket.
       * Doing an acive wait is not nice but there's nothing else
       * we seem to be able to do.
       */
      wait_for_virtio_host(serial_fd);

      if (opt_daemon) {
	server_daemonize();
	opt_daemon = false;
      }

      service_connection(serial_fd);
      close(serial_fd);
    } while (!opt_oneshot);
  } else
  if (!strcmp(opt_port_type, "unix")) {
    int listen_fd;

    listen_fd = open_unix_port(opt_port_path);
    if (listen_fd < 0)
      exit(TWOPENCE_SERVER_SOCKET_ERROR);

    if (opt_daemon) {
      server_daemonize();
      opt_daemon = false;
    }

    do {
      int sock_fd, retries = 0;

      while ((sock_fd = accept_unix_connection(listen_fd)) < 0) {
        if (++retries > 100) {
          fprintf(stderr, "... giving up.\n");
	  exit(TWOPENCE_SERVER_SOCKET_ERROR);
	}
        continue;
      }

      service_connection(sock_fd);
      close(sock_fd);
    } while (!opt_oneshot);
  } else {
    fprintf(stderr, "serial port type %s not yet implemented\n", opt_port_type);
    exit(TWOPENCE_SERVER_SOCKET_ERROR);
  }

  return 0;
}

void
service_connection(int serial_fd)
{
  server_run(socket_new(serial_fd));
}

void
server_daemonize(void)
{
  pid_t pid;

  pid = fork();
  if (pid < 0) {
    perror("test_server: unable to fork");
    exit(TWOPENCE_SERVER_FORK_ERROR);
  }

  if (pid != 0)
    exit(0);

  /* Close all stdio fds, and reconnect them to /dev/null.
   * We need to do this, because some of our functions
   * will currently print debugging and error messages to
   * stdout and stderr.
   */
  if (daemon(0, 0) < 0) {
    perror("test_server: unable to daemonize");
    exit(TWOPENCE_SERVER_FORK_ERROR);
  }

  server_log_file = NULL;
}

void
twopence_trace(const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  if (server_log_file) {
    vfprintf(server_log_file, fmt, ap);
  } else {
    vsyslog(LOG_DEBUG, fmt, ap);
  }
}
