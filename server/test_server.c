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

#define BUFFER_SIZE 32768              // bytes
#define LINE_TIMEOUT 5000              // milliseconds
#define COMMAND_TIMEOUT 12             // seconds
#define PASSIVE_WAIT 20000000L         // nanoseconds (this value is 1/50th of a second)
#define TWOPENCE_SERIAL_PORT_DEFAULT	"/dev/virtio-ports/org.opensuse.twopence.0"

#define TWOPENCE_SERVER_PARAMETER_ERROR -1
#define TWOPENCE_SERVER_SOCKET_ERROR -2

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

// Create four pipes : input, output, error, codes
//
// Returns 0 if everything went fine, a Linux error code otherwise
int create_pipes(int *std_parent, int *std_child)
{
  int pipe_fd[2], rc;

  if (pipe(pipe_fd) != 0)
  {
    rc = errno;
    return rc;
  }
  std_parent[0] = pipe_fd[1]; // write
  std_child[0] = pipe_fd[0]; // read

  if (pipe(pipe_fd) != 0)
  {
    rc = errno;
    close(std_parent[0]); close(std_child[0]);
    return rc;
  }
  std_parent[1] = pipe_fd[0]; // read
  std_child[1] = pipe_fd[1]; // write

  if (pipe(pipe_fd) != 0)
  {
    rc = errno;
    close(std_parent[0]); close(std_child[0]);
    close(std_parent[1]); close(std_child[1]);
    return rc;
  }
  std_parent[2] = pipe_fd[0]; // read
  std_child[2] = pipe_fd[1]; // write

  if (pipe(pipe_fd) != 0)
  {
    rc = errno;
    close(std_parent[0]); close(std_child[0]);
    close(std_parent[1]); close(std_child[1]);
    close(std_parent[2]); close(std_child[2]);
    return rc;
  }
  std_parent[3] = pipe_fd[0]; // read
  std_child[3] = pipe_fd[1]; // write

  return 0;
}

// Close four pipes on one side
void close_pipes(const int *std)
{
  const int *p;

  for (p = std; p < std + 4; p++)
    if (*p != -1)
      close(*p);
}

// Change user and working directory
int change_user_and_dir(const char *username)
{
  struct passwd *user;

  // Be lazy: if root is requested, we are already okay!
  if (!strcmp(username, "root"))
    return 0;

  // Search for usename in /etc/paswd, NIS, LDAP, and friends
  errno = 0;                           // Strange, but see "man getpwnam"
  user = getpwnam(username);
  if (user == NULL)
  {
    if (errno) return errno;
    return EINVAL;
  }

  // Set both real and effective uids
  if (setregid(user->pw_gid, user->pw_gid) < 0)
    return errno;
  if (setreuid(user->pw_uid, user->pw_uid) < 0)
    return errno;

  // Switch to the user's working directory
  if (chdir(user->pw_dir) < 0)
    return errno;

  return 0;
}

// Redirect standard input, output, and error
//
// Returns 0 if everything went fine, a Linux error code otherwise
int redirect_std_ports(const int *new_std)
{
  int std_port, new_port,
      flags;

  for (std_port = 0; std_port < 3; std_port++)
  { 
    new_port = new_std[std_port];      // Redirect to the new port
    if (dup2(new_port, std_port) < 0)
      return errno;

    flags = fcntl                      // We certainly don't want nonblocking stdin, stdout, or stderr ;-)
              (std_port, F_GETFL, 0);
    if (flags < 0)
      return errno;
    if (fcntl
          (std_port, F_SETFL, flags & ~O_NONBLOCK) < 0)
      return errno;
  }
  return 0;
}

// Sleep a short amount of time (to prevent active wait)
void short_sleep()
{
  struct timespec ts;

  ts.tv_sec = 0;
  ts.tv_nsec = PASSIVE_WAIT;
  nanosleep(&ts, NULL);
}

// Store length of data chunk to send
void store_length(int length, char *buffer)
{
  buffer[2] = (length & 0xFF00) >> 8;
  buffer[3] = length & 0xFF;
}

// Compute length of data chunk received
int compute_length(const void *data)
{
  const unsigned char *cp = (const unsigned char *) data;

  return (cp[2] << 8) | cp[3];
}

// Receive at most a maximum amount of bytes from the serial line
//
// Returns the number of bytes received, -1 otherwise.
int receive_buffer
      (int serial_fd, char *buffer, int maximum, int *rc)
{
  struct pollfd fds[1];
  int n, received;

  fds[0].fd = serial_fd;               // Wait either for input on the serial port or for a timeout
  fds[0].events = POLLIN;
  n = poll(fds, 1, LINE_TIMEOUT);
  if (n < 0)
  {
    *rc = errno;
    return -1;
  }

  if (n == 0)                          // Timeout
  {
    *rc = ETIME;
    return -1;
  }

  if (fds[0].revents & POLLIN)         // Receive on serial port
  {
    received = read(serial_fd, buffer, maximum);
    if (received < 0 && errno != EAGAIN)
    {
      *rc = errno;
      return -1;
    }
    if (received > 0)
      return received;
  }

  if (fds[0].revents & POLLHUP)        // poll() returns immediately when the host is disconnected
    short_sleep();                     // for that reason, we must ensure that we don't do an active wait

  *rc = 0;
  return 0;
}

// Receive at most a maximum amount of bytes from the serial line
// or from the Linux command's stdout and stderr
//
// Returns the number of bytes received, -1 otherwise.
int receive_buffer_2
      (int serial_fd, int *new_std, char *buffer, int maximum, int *rc)
{
  struct pollfd fds[3];
  int n, received;

  fds[0].fd = serial_fd;               // Wait either for input on the various ports or for a timeout
  fds[0].events = POLLIN;
  fds[1].fd = new_std[1];
  fds[1].events = POLLIN;
  fds[2].fd = new_std[2];
  fds[2].events = POLLIN;
  n = poll(fds, 3, LINE_TIMEOUT);
  if (n < 0)
  {
    *rc = errno;
    return -1;
  }

  if (n == 0)                          // Timeout
  {
    *rc = ETIME;
    return -1;
  }

  if (fds[0].revents & POLLIN)        // Receive on serial port
  {
    received = read(serial_fd, buffer, maximum);
    if (received < 0 && errno != EAGAIN)
    {
      *rc = errno;
      return -1;
    }
    if (received > 0)
      return received;
  }

  if (fds[1].revents & POLLIN)         // Receive on stdout
  {
    received = read(new_std[1], buffer + 4, BUFFER_SIZE - 4);
    if (received < 0 && errno != EAGAIN)
    {
      *rc = errno;
      return -1;
    }
    if (received > 0)
    {
      buffer[0] = '1';
      store_length(received + 4, buffer);
      return received + 4;
    }
  }

  if (fds[2].revents & POLLIN)         // Receive on stderr
  {
    received = read(new_std[2], buffer + 4, BUFFER_SIZE - 4);
    if (received < 0 && errno != EAGAIN)
    {
      *rc = errno;
      return -1;
    }
    if (received > 0)
    {
      buffer[0] = '2';
      store_length(received + 4, buffer);
      return received + 4;
    }
  }

  if (fds[0].revents & POLLHUP)        // poll() returns immediately when the host is disconnected
    short_sleep();                     // for that reason, we must ensure that we don't do an active wait

  *rc = 0;
  return 0;
}

// Send an amount of bytes.
//
// Returns the number of bytes sent, -1 otherwise.
int send_buffer
  (int serial_fd, char *buffer, int size, int *rc)
{
  struct pollfd fds[1];
  int n, sent;

  fds[0].fd = serial_fd;                 // Wait either for output on the serial port or for a timeout
  fds[0].events = POLLOUT;
  n = poll(fds, 1, LINE_TIMEOUT);
  if (n < 0)
  {
    *rc = errno;
    return -1;
  }
  if (n == 0)
  {
    *rc = ETIME;
    return -1;
  }

  sent = 0;                            // Send on serial port
  if (fds[0].revents & POLLOUT)
  {
    sent = write(serial_fd, buffer, size);
    if (sent < 0)
    {
      *rc = errno;
      return -1;
    }
  }
  return sent;
}

// Read a chunk from the serial line
//
// Returns 0 when everything went fine,
// a Linux error code otherwise.
int read_chunk(int serial_fd, char *buffer)
{
  int remaining;
  char *p;
  int rc, size, length;

  remaining = 4;                       // First try to read the header
  p = buffer;
  while (remaining > 0)
  {
    size = receive_buffer              // Receive less than the remaining amount of data
      (serial_fd, p, remaining, &rc);
    if (size < 0)
      return rc;

    remaining -= size;
    p += size;
  }

  length = compute_length(buffer);     // Decode the announced amount of data
  if (length > BUFFER_SIZE)
    return ENOMEM;

  remaining = length - 4;              // Read the announced amount of data
  while (remaining > 0)
  {
    size = receive_buffer              // Receive less than the remaining amount of data
      (serial_fd, p, remaining, &rc);
    if (size < 0)
      return rc;

    remaining -= size;
    p += size;
  }

  return 0;
}

// Read a chunk from the serial line or from the Linux command
//
// Unline read_chunk(), this function is nonblocking
//
// Returns 0 when everything went fine,
// a Linux error code otherwise.
int read_chunk_2(int serial_fd, int *new_std, char *buffer)
{
  int remaining;
  char *p;
  int rc, size, length;

  remaining = 4;                       // First try to read the header
  p = buffer;
  while (remaining > 0)
  {
    size = receive_buffer_2            // Receive less than the remaining amount of data
      (serial_fd, new_std, p, remaining, &rc);
    if (size <= 0)                     // Unlike read_chunk(), we don't block if there is nothing to read
      return rc;

    remaining -= size;
    p += size;
  }

  if (buffer[0] == '1' ||              // If that was input on stdout or stderr, we're done
      buffer[0] == '2') return 0;

  length = compute_length(buffer);     // Decode the announced amount of data
  if (length > BUFFER_SIZE)
    return ENOMEM;

  remaining = length - 4;              // Read the announced amount of data
  while (remaining > 0)
  {
    size = receive_buffer              // Receive less than the remaining amount of data
      (serial_fd, p, remaining, &rc);
    if (size < 0)
      return rc;

    remaining -= size;
    p += size;
  }

  return 0;
}

// Send a number of bytes in a buffer to the device
// Send it in several times to accomodate for slow lines
//
// Returns 0 if everything went fine, or a Linux error code otherwise
int send_big_buffer
  (int device_fd, char *buffer, int size)
{
  int rc, sent;

  while (size > 0)
  {
    sent = send_buffer
      (device_fd, buffer, size, &rc);
    if (sent == -1) return rc;

    buffer += sent;
    size -= sent;
  }

  return 0;
}

// Print a message to the host with a terminating NUL
void print_message(int serial_fd, const char *format, ...)
{
  static char message[128];
  va_list args;
  int length;

  va_start(args, format);              // Apply formatting
  vsnprintf(message, 127, format, args);
  va_end(args);
  message[127] = '\0';

  length = strlen(message) + 1;        // Fix the length before sending
  store_length(length, message);
  send_big_buffer                      // Send, error code is ignored
    (serial_fd, message, length);
}

////////////////////////////////////// Middle layer //////////////////////////

// Run a linux command under a given username
void linux_command(const char *username, const char *command, int *new_std)
{
  int rc;

  // Redirect the standard descriptors to the serial ports
  rc = redirect_std_ports(new_std);
  if (rc != 0)
  {
    print_message(new_std[3], "M...%d", rc);
    print_message(new_std[3], "m...%d", 0);
    return;
  }

  // Change user and working directory
  rc = change_user_and_dir(username);
  if (rc != 0)
  {
    print_message(new_std[3], "M...%d", rc);
    print_message(new_std[3], "m...%d", 0);
    return;
  }

  // Run the command
  alarm(COMMAND_TIMEOUT);
  rc = system(command);

  // Conclude with error codes
  // These lines rely on the way Linux constructs the return code of system()
  print_message(new_std[3], "M...%d", rc & 0xFF);
  print_message(new_std[3], "m...%d", rc >> 8);
}

// Forward the standard input-output to the Linux command
void forward_stdio(int serial_fd, int *new_std, int pid, char *buffer)
{
  int rc, received;

  rc = read_chunk_2                    // Receive stdio chunks
    (serial_fd, new_std, buffer);
  if (rc != 0) return;

  received = compute_length(buffer);   // Decode the header
  switch (buffer[0])
  {
    case '0':                          // stdin
      if (new_std[0] != -1)
        write(new_std[0], buffer + 4, received - 4);
      break;
    case 'E':                          // end of input
      close(new_std[0]);
      new_std[0] = -1;
      break;
    case '1':                          // stdout
    case '2':                          // stderr
      send_big_buffer(serial_fd, buffer, received);
      break;
    case 'I':                          // interrupt
      kill(pid, SIGKILL);
      break;
    case '-':                          // already read
      return;
  }
  buffer[0] = '-';                     // Mark buffer as already read
}

// Forward the major and minor error codes from the Linux command
void forward_major_minor(int serial_fd, int *new_std, char *buffer)
{
  int rc, received;

  rc = read_chunk                      // Receive the major
      (new_std[3], buffer);
  if (rc != 0 || buffer[0] != 'M')
    return;

  received = compute_length(buffer);   // Forward it
  send_big_buffer(serial_fd, buffer, received);

  rc = read_chunk                      // Receive the minor
      (new_std[3], buffer);
  if (rc != 0 || buffer[0] != 'm')
    return;

  received = compute_length(buffer);   // Forward it
  send_big_buffer(serial_fd, buffer, received);
}

// Receive an expected number of bytes from a file.
void receive_file(int serial_fd, int filesize, const char *username, const char *filename, char *buffer)
{
  int file_fd, rc,
      received, written;

  // Change user and working directory
  rc = change_user_and_dir(username);
  if (rc != 0)
  {
    rc = errno;
    print_message(serial_fd, "M...%d", rc);
    return;
  }

  // Open the file, creating it if it does not exist (u=rw,g=rw,o=)
  file_fd = creat(filename, 00660);
  if (file_fd < 0)
  {
    rc = errno;
    print_message(serial_fd, "M...%d", rc);
    return;
  }

  // Send first error code (before transfer)
  print_message(serial_fd, "M...0");

  // Receive the data from the serial line
  // and write them to the file in chunks
  while (filesize > 0)
  {
    rc = read_chunk                    // Read a chunk of data
      (serial_fd, buffer);
    if (rc != 0)
    {
      close(file_fd);
      print_message(serial_fd, "m...%d", rc);
      return;
    }

    if (buffer[0] != 'd')              // Decode the header
    {
      close(file_fd);
      print_message(serial_fd, "m...%d", EPROTO);
      return;
    }
    received = compute_length(buffer) - 4;

    if (received > 0)
    {
      written = write                  // Write the data to the file
        (file_fd, buffer + 4, received);
      if (written != received)
      {
        rc = written < 0?              // FIXME: not writing as much as we expected could be many things:
             errno:                    // returning EIO is underoptimal.
             EIO;
        close(file_fd);
        print_message(serial_fd, "m...%d", rc);
        return;
      }
    }
    filesize -= received;              // One chunk less to write
  }

  // Send second error code (after transfer)
  close(file_fd);
  print_message(serial_fd, "m...0");
  return;
}

// Send a file size and the file itself
void send_file
  (int serial_fd, const char *username, const char *filename, char *buffer)
{
  int file_fd, rc;
  struct stat filestats;
  int available, size, received;

  // Change user and working directory
  rc = change_user_and_dir(username);
  if (rc != 0)
  {
    rc = errno;
    print_message(serial_fd, "M...%d", rc);
    return;
  }

  // Open the file
  file_fd = open(filename, O_RDONLY);
  if (file_fd == -1)
  {
    rc = errno;
    print_message(serial_fd, "M...%d", rc);
    return;
  }

  // Compute file size and send it
  fstat(file_fd, &filestats);
  available = filestats.st_size;
  print_message(serial_fd, "s...%ld", available);

  // Send the file itself
  while (available > 0)
  {                                    // Read at most BUFFER_SIZE bytes from the file
    size = available < BUFFER_SIZE - 4?
           available:
           BUFFER_SIZE - 4;
    received = read(file_fd, buffer + 4, size);
    if (received < 0)
    {
      rc = errno;
      print_message(serial_fd, "M...%d", rc);
      close(file_fd);
      return;
    }

    if (received > 0)                  // Send the data to the host
    {
      buffer[0] = 'd';
      store_length(received + 4, buffer);
      rc = send_big_buffer(serial_fd, buffer, received + 4);
      if (rc != 0)
      {
        print_message(serial_fd, "M...%d", rc);
        close(file_fd);
        return;
      }
    }
    available -= received;             // One chunk less to read
  }

  // Close the file
  close(file_fd);
}

////////////////////////////////////// Top layer /////////////////////////////

// Run a Linux command.
void run_command(int serial_fd, char *buffer)
{
  int rc;
  char *username, *commandline;
  pid_t pid;
  int std_parent[4], std_child[4];
  int status;

  // Get the username and the Linux command
  sscanf(buffer + 4, "%ms %m[^\n]s", &username, &commandline);

  // Create pipes for communication between parent and child
  rc = create_pipes
    (std_parent, std_child);
  if (rc != 0)
  {
    print_message(serial_fd, "M...%d", rc);
    print_message(serial_fd, "m...%d", 0);
    free(username);
    free(commandline);
    return;
  }

  // Fork current process
  fflush(stdout);
  fflush(stderr);

  pid = fork();
  if (pid < 0)
  {
    rc = errno;
    print_message(serial_fd, "M...%d", rc);
    print_message(serial_fd, "m...%d", 0);
    close_pipes(std_parent);
    close_pipes(std_child);
    free(username);
    free(commandline);
    return;
  }

  // In the child process, run the command
  if (pid == 0)
  {
    close_pipes(std_parent);
    linux_command(username, commandline, std_child);
//  close_pipes(std_child);
    exit(0);
  }

  // In the parent process, wait for the child to exit
  close_pipes(std_child);
  while (waitpid                       // In the meantime, forward the standard input-output to the child
    (pid, &status, WNOHANG) == 0)
  {
    forward_stdio                      // We reuse the command buffer as we don't need it anymore
      (serial_fd, std_parent, pid, buffer);
  }
  if (WIFSIGNALED(status))             // If timeout or other signal
  {
    printf("        Timeout or other signal during execution of command.\n");
    forward_stdio                      // Then we may need to forward last data after child exited
      (serial_fd, std_parent, pid, buffer);
    print_message                      // and report the problem
      (serial_fd, "M...%d", ETIME);
    print_message
      (serial_fd, "m...%d", 0);
  }
  else if (WIFEXITED(status))          // If child process exited
  {
    forward_stdio                      // Then we may need to forward last data after child exited
      (serial_fd, std_parent, pid, buffer);
    forward_major_minor                // and forward the major and minor error codes to the serial interface
      (serial_fd, std_parent, buffer);
  }

  // Cleanup
  close_pipes(std_parent);
  free(username);
  free(commandline);
}

// Inject a file.
void inject_file(int serial_fd, char *buffer)
{
  int size;
  char *username, *filename;
  pid_t pid;

  // Get the username, the file size and the local name
  sscanf(buffer + 4, "%ms %d %m[^\n]s", &username, &size, &filename);

  // Let's fork, it enables to switch user
  // and to change the working directory without too many problems
  pid = fork();
  if (pid < 0)
  {
    free(username);
    free(filename);
    return;
  }

  // In the child process, receive the file
  // We reuse the command buffer as we don't need it anymore
  if (pid == 0)
  {
    receive_file
      (serial_fd, size, username, filename, buffer);
    exit(0);
  }

  // In the parent process, just wait for the child to exit()
  wait(NULL);

  free(username);
  free(filename);
}

// Extract a file.
void extract_file(int serial_fd, char *buffer)
{
  char *username, *filename;
  pid_t pid;

  // Get the username and the local name
  sscanf(buffer + 4, "%ms %m[^\n]s", &username, &filename);

  // Let's fork, it enables to switch user
  // and to change the working directory without too many problems
  pid = fork();
  if (pid < 0)
  {
    free(username);
    free(filename);
    return;
  }

  // In the child process, send the file
  // We reuse the command buffer as we don't need it anymore
  if (pid == 0)
  {
    send_file
      (serial_fd, username, filename, buffer);
    exit(0);
  }

  // In the parent process, just wait for the child to exit()
  wait(NULL);

  free(username);
  free(filename);
}

// Main entry point.
int main(int argc, char *argv[])
{
  static struct option long_opts[] = {
    { "port-serial", required_argument, NULL, 'S' },
    { "port-pty", no_argument, NULL, 'P' },
    { "port-unix", required_argument, NULL, 'U' },
    { NULL }
  };
  static char buffer[BUFFER_SIZE];
  const char *opt_port_type = NULL;
  const char *opt_port_path = NULL;
  int serial_fd;
  int command_num, rc;
  int c;

  // Welcome message, check arguments
  printf("Twopence test server version 0.3.0\n");

  while ((c = getopt_long(argc, argv, "P:S::U:", long_opts, NULL)) != -1) {
    switch (c) {
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
    serial_fd = open_serial_port(opt_port_path);
  } else {
    fprintf(stderr, "serial port type %s not yet implemented\n", opt_port_type);
    serial_fd = -1;
  }

  if (serial_fd < 0)
    exit(TWOPENCE_SERVER_SOCKET_ERROR);

  // Wait for commands
  command_num = 1;
  for (;;)
  {
    rc = read_chunk                    // Receive command from serial line
      (serial_fd, buffer);
    if (rc == ETIME)                   // Handle reception errors
    {
      continue;
    }
    if (rc != 0)
    {
      fprintf(stderr, "Read error\n");
      continue;
    }
    if (buffer[0] == 'q')              // Stop if exit requested
    {
      break;
    }
    else if (buffer[0] == 'c')         // Do proper action
    {
      printf("%6d command %s;\n", command_num++, buffer + 4);
      run_command(serial_fd, buffer);
    }
    else if (buffer[0] == 'i')
    {
      printf("%6d inject %s;\n", command_num++, buffer + 4);
      inject_file(serial_fd, buffer);
    }
    else if (buffer[0] == 'e')
    {
      printf("%6d extract %s;\n", command_num++, buffer + 4);
      extract_file(serial_fd, buffer);
    }
    else
    {
      fprintf(stderr, "Unknown command code '%c'\n", buffer[0]);
      continue;
    }
  }

  // Close the serial port and exit
  printf("Received \"exit\" command. Goodbye.\n");
  close(serial_fd);
  return 0 ;
}
