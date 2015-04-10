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
#include <netinet/in.h>

#include <pwd.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <termios.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <limits.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>

#include "server.h"

#define TWOPENCE_SERIAL_PORT_DEFAULT	"/dev/virtio-ports/org.opensuse.twopence.0"
#define TWOPENCE_UNIX_PORT_DEFAULT	"/var/run/twopence.sock"
#define TWOPENCE_TCP_PORT_DEFAULT	64123

#define TWOPENCE_SERVER_PARAMETER_ERROR -1
#define TWOPENCE_SERVER_SOCKET_ERROR -2
#define TWOPENCE_SERVER_FORK_ERROR -3

static void		server_daemonize(void);

bool			server_audit = true;
unsigned int		server_audit_seq;

struct server_port {
	const char *	type;
	const char *	arg;
};

////////////////////////////////////// Lower layer ///////////////////////////

// Open the serial port
//
// Returns the file descriptor if successful, -1 otherwise.
int open_serial_port(const char *filename)
{
  static bool reported_port = false;
  int serial_fd;
  struct termios tio;

  if (filename == NULL)
    filename = TWOPENCE_SERIAL_PORT_DEFAULT;

  // print only once, at startup of server
  if (server_audit && !reported_port) {
    twopence_trace("Listening on %s\n", filename);
    reported_port = true;
  }

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
      twopence_log_error("poll on serial fd: %m");
      if (nfail >= 10) {
	twopence_log_error("Giving up.\n");
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

      if (nloop++ == 0 && !server_audit)
        twopence_log_error("Waiting for someone to connect to host side socket\n");
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

  if (server_audit)
    twopence_trace("Listening on %s\n", filename);

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

/*
 * Open the tcp port
 *
 * Returns the file descriptor if successful, -1 otherwise.
 */
int open_tcp_port(const char *arg)
{
  struct sockaddr_in6 six;
  unsigned long port = 0;
  int listen_fd;

  if (arg != NULL && strcmp(arg, "default")) {
    char *end;

    port = strtoul(arg, &end, 0);
    if (port == ULONG_MAX || *end != '\0') {
      fprintf(stderr, "Unable to parse tcp port number \"%s\"\n", arg);
      return -1;
    }
  }

  if (port == 0)
    port = TWOPENCE_TCP_PORT_DEFAULT;

  if (server_audit) {
    twopence_trace("Listening on TCP port %lu\n", port);
    twopence_trace("ATTENTION: This service allows remote command execution with absolutely NO AUTHENTICATION!\n");
  }

  memset(&six, 0, sizeof(six));
  six.sin6_family = AF_INET6;
  six.sin6_port = htons(port);

  listen_fd = socket(PF_INET6, SOCK_STREAM, 0);
  if (listen_fd < 0) {
    fprintf(stderr, "Unable to open ipv6 socket: %m\n");
    goto failed;
  }

  if (bind(listen_fd, (struct sockaddr *) &six, sizeof(six)) < 0) {
    fprintf(stderr, "Unable to bind tcp socket to port %lu: %m\n", port);
    goto failed;
  }

  if (listen(listen_fd, 0) < 0) {
    fprintf(stderr, "Unable to listen on tcp port %lu: %m\n", port);
    goto failed;
  }

  return listen_fd;

failed:
  if (listen_fd >= 0)
    close(listen_fd);
  return -1;
}

/*
 * Set the port type and name/number
 */
static bool
server_set_port(struct server_port *port, const char *type, const char *name)
{
  if (port->type != NULL) {
    fprintf(stderr, "Conflicting port types specified on command line\n");
    return false;
  }

  port->type = type;
  port->arg = name;
  return true;
}

//////////////////////////////////////////////////////////////////
// Main entry point.
//////////////////////////////////////////////////////////////////
int main(int argc, char *argv[])
{
  enum { OPT_ONESHOT, OPT_AUDIT, OPT_NOAUDIT };
  static struct option long_opts[] = {
    { "one-shot", no_argument, NULL, OPT_ONESHOT },
    { "port-serial", required_argument, NULL, 'S' },
    { "port-pty", no_argument, NULL, 'P' },
    { "port-unix", required_argument, NULL, 'U' },
    { "port-tcp", required_argument, NULL, 'T' },
    { "daemon", no_argument, NULL, 'D' },
    { "debug", no_argument, NULL, 'd' },
    { "audit", no_argument, NULL, OPT_AUDIT },
    { "no-audit", no_argument, NULL, OPT_NOAUDIT },
    { NULL }
  };
  int opt_oneshot = 0;
  struct server_port opt_port;
  bool opt_daemon = false;
  int c;

  // Welcome message, check arguments
  printf("Twopence test server version 0.3.3\n");

  /* Initially, debug logging goes to stderr */
  twopence_logging_init();

  memset(&opt_port, 0, sizeof(opt_port));
  while ((c = getopt_long(argc, argv, "DdPS:U:", long_opts, NULL)) != -1) {
    switch (c) {
    case OPT_ONESHOT:
      opt_oneshot = 1;
      break;

    case 'd':
      twopence_debug_level++;
      break;

    case 'D':
      opt_daemon = true;
      break;

    case 'S':
      if (!server_set_port(&opt_port, "serial", optarg))
	goto usage;
      break;

    case 'P':
      if (!server_set_port(&opt_port, "pty", optarg))
	goto usage;
      break;

    case OPT_AUDIT:
      server_audit = true;
      break;

    case OPT_NOAUDIT:
      server_audit = false;
      break;

    case 'U':
      if (!server_set_port(&opt_port, "unix", optarg))
	goto usage;
      break;

    case 'T':
      if (!server_set_port(&opt_port, "tcp", optarg))
	goto usage;
      break;

    default:
    usage:
	fprintf(stderr,
		"Usage:\n"
		"%s [options] <portspec>\n"
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
		"--port-tcp number:\n"
		"    create a TCP socket and listen on the given port number for incoming connections\n"
		"\n"
		"Supported options:\n"
		"--daemon\n"
		"    Background the server process and run it as a daemon\n"
		"--debug, -d\n"
		"    Increase debugging verbosity\n"
		"--one-shot\n"
		"    Service one incoming connection, then exit (only supported with serial ports)\n"
		"--audit\n"
		"    Print an audit trail of operations to the log (default)\n"
		"--no-audit\n"
		"    Disable the audit trail\n"
		"\n"
		"The default serial port is %s\n"
		, argv[0], TWOPENCE_SERIAL_PORT_DEFAULT);
        exit(TWOPENCE_SERVER_PARAMETER_ERROR);
    }
  }

  if (opt_port.type == NULL) {
    opt_port.type = "serial";
    if (optind < argc)
      opt_port.arg = argv[optind++];
  }

  if (optind < argc) {
    fprintf(stderr, "Too many arguments\n");
    goto usage;
  }

  /* Open the port */
  if (!strcmp(opt_port.type, "serial")) {
    int serial_fd;

    do {
      serial_fd = open_serial_port(opt_port.arg);
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

      server_run(twopence_sock_new(serial_fd));
    } while (!opt_oneshot);
  } else
  if (!strcmp(opt_port.type, "unix")) {
    int listen_fd;

    listen_fd = open_unix_port(opt_port.arg);
    if (listen_fd < 0)
      exit(TWOPENCE_SERVER_SOCKET_ERROR);

    if (opt_daemon) {
      server_daemonize();
      opt_daemon = false;
    }

    do {
      server_listen(twopence_sock_new(listen_fd));
    } while (!opt_oneshot);
  } else
  if (!strcmp(opt_port.type, "tcp")) {
    int listen_fd;

    listen_fd = open_tcp_port(opt_port.arg);
    if (listen_fd < 0)
      exit(TWOPENCE_SERVER_SOCKET_ERROR);

    if (opt_daemon) {
      server_daemonize();
      opt_daemon = false;
    }

    do {
      server_listen(twopence_sock_new(listen_fd));
    } while (!opt_oneshot);
  } else {
    fprintf(stderr, "serial port type %s not yet implemented\n", opt_port.type);
    exit(TWOPENCE_SERVER_SOCKET_ERROR);
  }

  return 0;
}

void
server_daemonize(void)
{
  pid_t pid;

  pid = fork();
  if (pid < 0) {
    twopence_log_error("test_server: unable to fork: %m");
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
    twopence_log_error("test_server: unable to daemonize: %m");
    exit(TWOPENCE_SERVER_FORK_ERROR);
  }

  /* Stop logging to stderr, write to syslog instead */
  twopence_set_logfile(NULL);
  twopence_set_syslog(true);
}
