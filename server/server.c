/*
 * Server semantic
 * 
 * The idea is to avoid interfering with networks test. This enables to test
 * even with all network interfaces are shut down.
 * 
 * 
 * Copyright (C) 2014-2015 SUSE
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h> /* for htons */

#include <pwd.h>
#include <grp.h>
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
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <ctype.h>
#include <limits.h>

#include "server.h"


static twopence_conn_t *	server_new_connection(twopence_sock_t *, twopence_conn_semantics_t *);

static struct passwd *
server_get_user(const char *username, int *status)
{
	struct passwd *pwd;

	pwd = getpwnam(username);
	if (pwd == NULL)
		*status = ENOENT;

	return pwd;
}

struct saved_ids {
	uid_t		uid;
	gid_t		gid;
};

static void
server_restore_privileges(struct saved_ids *saved_ids)
{
	if (saved_ids->uid == -1)
		return;

	seteuid(saved_ids->uid);
	if (geteuid() != saved_ids->uid) {
		twopence_log_error("Unable to restore previous uid %u: abort\n", saved_ids->uid);
		abort();
	}

	setegid(saved_ids->gid);
	if (getegid() != saved_ids->gid) {
		twopence_log_error("Unable to restore previous gid %u: abort\n", saved_ids->gid);
		abort();
	}
}

static const char *
server_build_path(const char *dir, const char *file)
{
	static char pathbuf[PATH_MAX];
	unsigned int total;

	/* snprintf returns the number it would have printed if the buffer
	 * was big enough. This allows us to check quickly for names that
	 * would exceed PATH_MAX */
	total = snprintf(pathbuf, sizeof(pathbuf), "%s/%s", dir, file);
	if (total >= sizeof(pathbuf))
		return NULL;

	return pathbuf;
}

static bool
server_change_hats_temporarily(const struct passwd *user, struct saved_ids *saved_ids, int *status)
{
	/* Do nothing for the root user */
	if (!strcmp(user->pw_name, "root")) {
		saved_ids->uid = -1;
		return true;
	}

	saved_ids->uid = getuid();
	saved_ids->gid = getgid();

	if (initgroups(user->pw_name, user->pw_gid) < 0
	 || setegid(user->pw_gid) < 0
	 || seteuid(user->pw_uid) < 0) {
		*status = errno;
		twopence_log_error("Unable to drop privileges to become user %s: %m", user->pw_name);
		server_restore_privileges(saved_ids);
		return false;
	}

	return true;
}

static bool
server_change_hats_permanently(const struct passwd *user, int *status)
{
	/* Do nothing for the root user */
	if (!strcmp(user->pw_name, "root"))
		return true;

	if (initgroups(user->pw_name, user->pw_gid) < 0
	 || setgid(user->pw_gid) < 0
	 || setuid(user->pw_uid) < 0) {
		*status = errno;
		twopence_log_error("Unable to drop privileges to become user %s: %m", user->pw_name);
		return false;
	}

	return true;
}

int
server_open_file_as(const char *username, const char *filename, unsigned int filemode, int oflags, int *status)
{
	struct stat stb;
	struct saved_ids saved_ids;
	struct passwd *user;
	int fd;

	if (!(user = server_get_user(username, status))) {
		twopence_debug("Unknown user \"%s\"\n", username);
		return -1;
	}

	/* If the path is not absolute, interpret it relatively to the
	 * user's home directory */
	if (filename[0] != '/') {
		filename = server_build_path(user->pw_dir, filename);
		if (filename == NULL) {
			twopence_log_error("Unable to build path from user %s's home \"%s\" and relative name \"%s\"\n",
					username, user->pw_dir, filename);
			*status = ENAMETOOLONG;
			return false;
		}
	}

	twopence_debug("%s(user=%s, file=%s, flags=0%0)\n", __func__, username, filename, oflags);

	/* We may want to have the client specify the file mode as well */
	if (!strcmp(username, "root")) {
		fd = open(filename, oflags, filemode);
		if (fd < 0)
			*status = errno;
	} else {
		if (!server_change_hats_temporarily(user, &saved_ids, status))
			return -1;
		fd = open(filename, oflags, filemode);
		if (fd < 0)
			*status = errno;

		server_restore_privileges(&saved_ids);
	}

	if (fd < 0)
		return -1;

	if (fstat(fd, &stb) < 0) {
		*status = errno;
		twopence_log_error("failed to stat \"%s\": %m", filename);
		close(fd);
		return -1;
	}
	if (!S_ISREG(stb.st_mode)) {
		twopence_log_error("%s: not a regular file\n", filename);
		*status = EISDIR;
		close(fd);
		return -1;
	}
	if (oflags != O_RDONLY && fchmod(fd, filemode) < 0) {
		*status = errno;
		twopence_log_error("failed to change file mode \"%s\" to 0%o: %m", filename, filemode);
		close(fd);
		return -1;
	}

	return fd;
}

long
server_file_size(const char *filename, int fd, int *status)
{
	struct stat stb;

	if (fstat(fd, &stb) < 0) {
		*status = errno;
		twopence_log_error("%s: unable to stat: %m\n", filename);
		return -1;
	}
	if (!S_ISREG(stb.st_mode)) {
		twopence_log_error("%s: not a regular file\n", filename);
		*status = EISDIR;
		return -1;
	}
	return stb.st_size;
}

bool
server_file_exists(const char *filename)
{
	struct stat stb;

	if (stat(filename, &stb) < 0)
		return false;
	return true;
}

static inline void
__init_fds(int *fd_list, int fd0, int fd1, int fd2)
{
	fd_list[0] = fd0;
	fd_list[1] = fd1;
	fd_list[2] = fd2;
}

static inline void
__close_fds(int *fd_list)
{
	close(fd_list[0]);
	close(fd_list[1]);
	close(fd_list[2]);
}

static char **
server_parse_cmdline(char *cmdline)
{
	char **argv, *s;
	int argc;

	twopence_debug("%s(\"%s\")\n", __func__, cmdline);

	s = cmdline;

	argc = 0;
	argv = NULL;
	while (true) {
		while (isspace(*s))
			++s;
		if (*s == '\0')
			break;

		if ((argc % 16) == 0)
			argv = realloc(argv, (argc + 16) * sizeof(argv[0]));

		if (*s == '"') {
			char cc, *t;

			argv[argc++] = ++s;
			t = s;
			while ((cc = *s++) != '\0') {
				if (cc == '\\') {
					if (*s == '\0')
						goto failed;
					cc = *s++;
				} else if (cc == '"')
					break;

				*t++ = cc;
			}
			*t++ = '\0';
		} else
		if (*s == '\'') {
			argv[argc++] = ++s;
			while (*s != '\'') {
				if (*s == '\0')
					goto failed;
				++s;
			}
			*s++ = '\0';
		} else {
			argv[argc++] = s;
			while (*s && !isspace(*s))
				++s;
			if (*s)
				*s++ = '\0';
		}
	}

	argv[argc] = NULL;
	return argv;

failed:
	free(argv);
	return NULL;

}

const char *
server_path_find_bin(const char *argv0)
{
	static const char *path_dir[] = {
		"/bin",
		"/sbin",
		"/usr/bin",
		"/usr/sbin",
		"/usr/local/bin",
		"/usr/local/sbin",
		NULL
	};
	unsigned int n;

	if (*argv0 == '/')
		return argv0;

	for (n = 0; path_dir[n]; ++n) {
		const char *path;

		path = server_build_path(path_dir[n], argv0);
		if (server_file_exists(path))
			return path;
	}

	return NULL;
}

int
server_run_command_as(const char *username, unsigned int timeout, const char *cmdline, int *parent_fds, int *status)
{
	int pipefds[6], child_fds[3];
	char *cmdline_copy = NULL, **argv = NULL;
	struct passwd *user;
	const char *argv0;
	int nfds = 0;
	pid_t pid = -1;

	if (!(user = server_get_user(username, status)))
		return -1;

	memset(pipefds, 0xa5, sizeof(pipefds));
	for (nfds = 0; nfds < 3; ++nfds) {
		if (pipe(pipefds + 2 * nfds) < 0) {
			*status = errno;
			goto failed;
		}
	}

	__init_fds(child_fds,  pipefds[0], pipefds[3], pipefds[5]); /* read-write-write */
	__init_fds(parent_fds, pipefds[1], pipefds[2], pipefds[4]); /* write-read-read */

	/* This whole cmdline business isn't really optimal, as it requires us to
	 * use a shell process inbetween */
	cmdline_copy = strdup(cmdline);
	argv = server_parse_cmdline(cmdline_copy);
	if (argv == NULL) {
		*status = EINVAL;
		goto failed;
	}

	{
		int n;

		twopence_debug("command argv[] =\n");
		for (n = 0; argv[n]; ++n)
			twopence_debug("   [%d] = \"%s\"\n", n, argv[n]);
	}

	argv0 = argv[0];
	if (*argv0 != '/') {
		argv0 = server_path_find_bin(argv[0]);
		if (argv0 == NULL) {
			*status = ENOENT;
			goto failed;
		}
	}

	pid = fork();
	if (pid < 0) {
		*status = errno;
		twopence_log_error("unable to fork: %m\n");
		goto failed;
	}
	if (pid == 0) {
		int fd, numfds;

		/* Child */
		__close_fds(parent_fds);

		dup2(child_fds[0], 0);
		dup2(child_fds[1], 1);
		dup2(child_fds[2], 2);

		numfds = getdtablesize();
		for (fd = 3; fd < numfds; ++fd)
			close(fd);

		if (!server_change_hats_permanently(user, status))
			exit(126);

		alarm(timeout? timeout : DEFAULT_COMMAND_TIMEOUT);

		/* Note: we may want to pass a standard environment, too */
		execv(argv0, argv);

		twopence_log_error("unable to run %s: %m", argv0);
		exit(127);
	}

	__close_fds(child_fds);

out:
	if (argv)
		free(argv);
	if (cmdline_copy)
		free(cmdline_copy);
	return pid;

failed:
	while (nfds--) {
		close(pipefds[2 * nfds]);
		close(pipefds[2 * nfds + 1]);
	}
	goto out;
}

static void
server_inject_file_write_eof(twopence_transaction_t *trans, twopence_trans_channel_t *channel)
{
	/* The channel may have data queued to it. For now, just flush it synchronously */
	twopence_transaction_channel_flush(channel);

	twopence_transaction_send_minor(trans, 0);
	trans->done = true;
}

bool
server_inject_file(twopence_transaction_t *trans, const char *username, const char *filename, size_t filemode)
{
	twopence_trans_channel_t *sink;
	int status;
	int fd;

	AUDIT("inject \"%s\"; user=%s\n", filename, username);
	if ((fd = server_open_file_as(username, filename, filemode, O_WRONLY|O_CREAT|O_TRUNC, &status)) < 0) {
		twopence_transaction_fail(trans, status);
		return false;
	}

	sink = twopence_transaction_attach_local_sink(trans, fd, TWOPENCE_PROTO_TYPE_DATA);
	if (sink == NULL) {
		/* Something is wrong */
		close(fd);
		return false;
	}

	twopence_transaction_channel_set_callback_write_eof(sink, server_inject_file_write_eof);

	/* Tell the client a success status right after we open the file -
	 * this will start the actual transfer */
	twopence_transaction_send_major(trans, 0);

	return true;
}

void
server_extract_file_source_read_eof(twopence_transaction_t *trans, twopence_trans_channel_t *channel)
{
	twopence_transaction_send_client(trans, twopence_protocol_build_eof_packet(&trans->ps));
	trans->done = true;
}

bool
server_extract_file(twopence_transaction_t *trans, const char *username, const char *filename)
{
	twopence_trans_channel_t *source;
	int status;
	int fd;

	AUDIT("extract \"%s\"; user=%s\n", filename, username);
	if ((fd = server_open_file_as(username, filename, 0600, O_RDONLY, &status)) < 0) {
		twopence_transaction_fail(trans, status);
		return false;
	}

	source = twopence_transaction_attach_local_source(trans, fd, TWOPENCE_PROTO_TYPE_DATA);
	if (source == NULL) {
		/* Something is wrong */
		twopence_transaction_fail(trans, EIO);
		close(fd);
		return false;
	}

	twopence_transaction_channel_set_callback_read_eof(source, server_extract_file_source_read_eof);

	/* We don't expect to receive any packets; sending is taken care of at the channel level */
	return true;
}

bool
server_run_command_send(twopence_transaction_t *trans)
{
	twopence_trans_channel_t *channel;
	int status;
	pid_t pid;
	bool pending_output;

	pending_output = false;
	if ((channel = twopence_transaction_find_source(trans, TWOPENCE_PROTO_TYPE_STDOUT)) != NULL
	 && !twopence_transaction_channel_is_read_eof(channel))
		pending_output = true;
	if ((channel = twopence_transaction_find_source(trans, TWOPENCE_PROTO_TYPE_STDERR)) != NULL
	 && !twopence_transaction_channel_is_read_eof(channel))
		pending_output = true;

	if (trans->pid) {
		pid = waitpid(trans->pid, &status, WNOHANG);
		if (pid > 0) {
			twopence_debug("%s: process exited, status=%u\n", twopence_transaction_describe(trans), status);
			twopence_transaction_close_sink(trans, 0);
			trans->status = status;
			trans->pid = 0;
		}
	}

	if (!trans->done && trans->pid == 0 && !pending_output) {
		int st = trans->status;

		if (WIFEXITED(st)) {
			twopence_transaction_send_major(trans, 0);
			twopence_transaction_send_minor(trans, WEXITSTATUS(st));
		} else
		if (WIFSIGNALED(st)) {
			if (WTERMSIG(st) == SIGALRM) {
				twopence_transaction_send_timeout(trans);
			} else {
				twopence_transaction_fail2(trans, EFAULT, WTERMSIG(st));
			}
		} else {
			twopence_transaction_fail2(trans, EFAULT, 2);
		}
		trans->done = true;
	}

	return true;
}

static void
server_run_command_stdin_eof(twopence_transaction_t *trans, twopence_trans_channel_t *sink)
{
	/* Nothing to be done. */
}

bool
server_run_command_recv(twopence_transaction_t *trans, const twopence_hdr_t *hdr, twopence_buf_t *payload)
{
	switch (hdr->type) {
	case TWOPENCE_PROTO_TYPE_INTR:
		/* Send signal to process, and shut down all I/O.
		 * When we send a signal, we're not really interested in what
		 * it has to say, not even "aargh".
		 */
		if (trans->pid && !trans->done) {
			kill(trans->pid, SIGKILL);
			twopence_transaction_close_sink(trans, 0);
			twopence_transaction_close_source(trans, 0); /* ID zero means all */
		}
		break;

	default:
		twopence_log_error("Unknown command code '%c' in transaction context\n", hdr->type);
		break;
	}

	return true;
}

bool
server_run_command(twopence_transaction_t *trans, const char *username, unsigned int timeout, const char *cmdline)
{
	twopence_trans_channel_t *sink;
	int status;
	int command_fds[3];
	int nattached = 0;
	pid_t pid;

	AUDIT("run \"%s\"; user=%s timeout=%u\n", cmdline, username, timeout);
	if ((pid = server_run_command_as(username, timeout, cmdline, command_fds, &status)) < 0) {
		twopence_transaction_fail2(trans, status, 0);
		return false;
	}

	sink = twopence_transaction_attach_local_sink(trans, command_fds[0], TWOPENCE_PROTO_TYPE_STDIN);
	if (sink == NULL)
		goto failed;
	twopence_transaction_channel_set_callback_write_eof(sink, server_run_command_stdin_eof);
	nattached++;

	if (twopence_transaction_attach_local_source(trans, command_fds[1], TWOPENCE_PROTO_TYPE_STDOUT) == NULL)
		goto failed;
	nattached++;

	if (twopence_transaction_attach_local_source(trans, command_fds[2], TWOPENCE_PROTO_TYPE_STDERR) == NULL)
		goto failed;
	nattached++;

	trans->recv = server_run_command_recv;
	trans->send = server_run_command_send;
	trans->pid = pid;

	return true;

failed:
	twopence_transaction_fail2(trans, EIO, 0);
	while (nattached < 3)
		close(command_fds[nattached++]);
	return false;
}

/*
 * Handle incoming HELLO packet. Respond with the ID we assigned to the client
 */
bool
server_request_quit(void)
{
	exit(0);
}

bool
server_process_request(twopence_transaction_t *trans, twopence_buf_t *payload)
{
	char username[128];
	char filename[PATH_MAX];
	char command[2048];
	unsigned int filemode = 0;
	unsigned int timeout = 0;

	switch (trans->type) {
	case TWOPENCE_PROTO_TYPE_HELLO:
		twopence_sock_queue_xmit(trans->socket,
				twopence_protocol_build_hello_packet(trans->ps.cid));
		trans->done = true;
		break;

	case TWOPENCE_PROTO_TYPE_INJECT:
		if (!twopence_protocol_dissect_string(payload, username, sizeof(username))
		 || !twopence_protocol_dissect_uint(payload, &filemode)
		 || !twopence_protocol_dissect_string(payload, filename, sizeof(filename)))
			goto bad_packet;

		server_inject_file(trans, username, filename, filemode);
		break;

	case TWOPENCE_PROTO_TYPE_EXTRACT:
		if (!twopence_protocol_dissect_string(payload, username, sizeof(username))
		 || !twopence_protocol_dissect_string(payload, filename, sizeof(filename)))
			goto bad_packet;

		server_extract_file(trans, username, filename);
		break;

	case TWOPENCE_PROTO_TYPE_COMMAND:
		if (!twopence_protocol_dissect_string(payload, username, sizeof(username))
		 || !twopence_protocol_dissect_uint(payload, &timeout)
		 || !twopence_protocol_dissect_string_delim(payload, command, sizeof(command), '\n')
		 || command[0] == '\0')
			goto bad_packet;

		server_run_command(trans, username, timeout, command);
		break;

	case TWOPENCE_PROTO_TYPE_QUIT:
		server_request_quit();
		/* we should not get here */
		trans->done = true;
		break;

	default:
		twopence_log_error("Unknown command code '%c' in global context\n", trans->type);
		return false;
	}

	return true;

bad_packet:
	twopence_log_error("unable to parse %c packet", trans->type);
	return false;
}

static twopence_conn_semantics_t	server_ops = {
	.process_request	= server_process_request,
};

/*
 * Sockets in listen mode.
 */
int
server_listen_doio(twopence_conn_pool_t *poll, twopence_conn_t *conn)
{
	twopence_sock_t *sock;

	sock = twopence_conn_accept(conn);
	if (sock != NULL) {
		twopence_debug("Accepted incoming connection");
		twopence_conn_pool_add_connection(poll, server_new_connection(sock, &server_ops));
	}
	return 0;
}

static twopence_conn_semantics_t	listen_ops = {
	.doio			= server_listen_doio,
};

static void
child_handler(int sig)
{
}

static twopence_conn_t *
server_new_connection(twopence_sock_t *sock, twopence_conn_semantics_t *semantics)
{
	static unsigned int global_client_id = 1;

	return twopence_conn_new(semantics,  sock, global_client_id++);
}

static void
__server_run(twopence_conn_t *conn)
{
	twopence_conn_pool_t *pool;
	struct sigaction sa;
	sigset_t mask, omask;

	/* Block delivery of SIGCHLD while we're about and executing something.
	 * We use ppoll to enable SIGCHLD, so that there is only one defined
	 * place to receive that signal. */
	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &mask, &omask);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = child_handler;
	sigaction(SIGCHLD, &sa, NULL);

	signal(SIGPIPE, SIG_IGN);

	pool = twopence_conn_pool_new();

	twopence_conn_pool_add_connection(pool, conn);
	while (twopence_conn_pool_poll(pool))
		;

	sigprocmask(SIG_SETMASK, &omask, NULL);

	/* FIXME: */
	/* twopence_conn_pool_free(pool); */
}

void
server_run(twopence_sock_t *sock)
{
	__server_run(server_new_connection(sock, &server_ops));
}

void
server_listen(twopence_sock_t *sock)
{
	__server_run(server_new_connection(sock, &listen_ops));
}
