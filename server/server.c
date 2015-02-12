/*
 * Server semanticServer semantics
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
		TRACE("Unknown user \"%s\"\n", username);
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

	TRACE("%s(user=%s, file=%s, flags=0%0)\n", __func__, username, filename, oflags);

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

	TRACE("%s(\"%s\")\n", __func__, cmdline);

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

		TRACE("command argv[] =\n");
		for (n = 0; argv[n]; ++n)
			TRACE("   [%d] = \"%s\"\n", n, argv[n]);
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

bool
server_inject_file_recv(transaction_t *trans, const header_t *hdr, twopence_buf_t *payload)
{
	switch (hdr->type) {
	case PROTO_HDR_TYPE_DATA:
		TRACE("inject: received %u bytes of data\n", twopence_buf_count(payload));
		transaction_write_data(trans, payload);
		/* FIXME: how do we propagate write errors to the client? */
		break;

	case PROTO_HDR_TYPE_EOF:
		TRACE("inject: received EOF\n");
		transaction_send_minor(trans, 0);
		socket_shutdown_write(trans->local_sink);
		trans->done = true;
		break;

	default:
		twopence_log_error("Unknown command code '%c' in transaction context\n", hdr->type);
		transaction_fail(trans, EPROTO);
		break;
	}
	return true;
}

bool
server_inject_file(transaction_t *trans, const char *username, const char *filename, size_t filemode)
{
	int status;
	int fd;

	if ((fd = server_open_file_as(username, filename, filemode, O_WRONLY|O_CREAT|O_TRUNC, &status)) < 0) {
		transaction_fail(trans, status);
		return false;
	}

	if (!transaction_attach_local_sink(trans, fd)) {
		/* Something is wrong */
		close(fd);
		return false;
	}

	/* Tell the client a success status right after we open the file -
	 * this will start the actual transfer */
	transaction_send_major(trans, 0);

	/* Ignore the file size - we're no longer interested in it */
	trans->recv = server_inject_file_recv;

	return true;
}

bool
server_extract_file_recv(transaction_t *trans, const header_t *hdr, twopence_buf_t *payload)
{
	switch (hdr->type) {
	default:
		twopence_log_error("Unknown command code '%c' in transaction context\n", hdr->type);
		transaction_fail(trans, EPROTO);
		break;
	}
	return true;
}

bool
server_extract_file_send(transaction_t *trans)
{
	socket_t *sock;
	twopence_buf_t *bp;

	TRACE("%s()\n", __func__);
	if (trans->num_local_sources == 0)
		return false;
	if ((sock = trans->local_source[0]) == NULL)
		return false;

	bp = socket_take_recvbuf(sock);
	if (bp != NULL) {
		/* Add a header to the packet and send it out */
		protocol_push_header(bp, PROTO_HDR_TYPE_DATA);
		transaction_send_client(trans, bp);
	}

	if (socket_is_read_eof(sock)) {
		TRACE("EOF on extracted file");
		transaction_send_client(trans, protocol_build_eof_packet());
		transaction_close_source(trans, 0);
		trans->done = true;
	}
	return true;
}

bool
server_extract_file(transaction_t *trans, const char *username, const char *filename)
{
	int status;
	int fd;

	if ((fd = server_open_file_as(username, filename, 0600, O_RDONLY, &status)) < 0) {
		transaction_fail(trans, status);
		return false;
	}

	if (!transaction_attach_local_source(trans, fd)) {
		/* Something is wrong */
		transaction_fail(trans, EIO);
		close(fd);
		return false;
	}

	trans->recv = server_extract_file_recv;
	trans->send = server_extract_file_send;

	return true;
}

bool
server_run_command_send(transaction_t *trans)
{
	unsigned int i;
	socket_t *sock;
	int status;
	pid_t pid;
	bool pending_output;

	pending_output = false;
	for (i = 0; i < trans->num_local_sources; ++i) {
		twopence_buf_t *bp;

		if (!(sock = trans->local_source[i]))
			continue;

		bp = socket_take_recvbuf(sock);
		if (bp != NULL) {
			TRACE("read %u bytes from command fd %d\n", twopence_buf_count(bp), i + 1);
			protocol_push_header(bp, PROTO_HDR_TYPE_STDOUT + i);

			socket_queue_xmit(trans->client_sock, bp);
			socket_post_recvbuf(sock, protocol_command_buffer_new());
		}

		if (socket_is_dead(sock))
			transaction_close_source(trans, i);
		else
			pending_output = true;
	}

	if (trans->pid) {
		pid = waitpid(trans->pid, &status, WNOHANG);
		if (pid > 0) {
			TRACE("process exited, status=%u\n", status);
			transaction_close_sink(trans);
			trans->status = status;
			trans->pid = 0;
		}
	}

	if (!trans->done && trans->pid == 0 && !pending_output) {
		int st = trans->status;

		if (WIFEXITED(st)) {
			transaction_send_major(trans, 0);
			transaction_send_minor(trans, WEXITSTATUS(st));
		} else
		if (WIFSIGNALED(st)) {
			if (WTERMSIG(st) == SIGALRM) {
				transaction_send_timeout(trans);
			} else {
				transaction_fail2(trans, EFAULT, WTERMSIG(st));
			}
		} else {
			transaction_fail2(trans, EFAULT, 2);
		}
		trans->done = true;
	}

	return true;
}

bool
server_run_command_recv(transaction_t *trans, const header_t *hdr, twopence_buf_t *payload)
{
	switch (hdr->type) {
	case PROTO_HDR_TYPE_STDIN:
		/* queue the buffer for output to the local command */
		transaction_queue_stdin(trans, twopence_buf_clone(payload));
		break;

	case PROTO_HDR_TYPE_EOF:
		transaction_write_eof(trans);
		break;

	case PROTO_HDR_TYPE_INTR:
		/* Send signal to process, and shut down all I/O.
		 * When we send a signal, we're not really interested in what
		 * it has to say, not even "aargh".
		 */
		if (trans->pid && !trans->done) {
			int n;

			kill(trans->pid, SIGKILL);
			transaction_close_sink(trans);
			for (n = 0; n < TRANSACTION_MAX_SOURCES; ++n)
				transaction_close_source(trans, n);
		}
		break;

	default:
		twopence_log_error("Unknown command code '%c' in transaction context\n", hdr->type);
		break;
	}

	return true;
}

bool
server_run_command(transaction_t *trans, const char *username, unsigned int timeout, const char *cmdline)
{
	int status;
	int command_fds[3];
	int nattached = 0;
	pid_t pid;

	if ((pid = server_run_command_as(username, timeout, cmdline, command_fds, &status)) < 0) {
		transaction_fail2(trans, status, 0);
		return false;
	}

	if (!transaction_attach_local_sink(trans, command_fds[0]))
		goto failed;
	nattached++;

	while (nattached < 3) {
		if (!transaction_attach_local_source(trans, command_fds[nattached]))
			goto failed;
		nattached++;
	}

	trans->recv = server_run_command_recv;
	trans->send = server_run_command_send;
	trans->pid = pid;

	return true;

failed:
	transaction_fail2(trans, EIO, 0);
	while (nattached < 3)
		close(command_fds[nattached++]);
	return false;
}

static semantics_t	server_ops = {
	.inject_file		= server_inject_file,
	.extract_file		= server_extract_file,
	.run_command		= server_run_command,
};

static void
child_handler(int sig)
{
}

void
server_run(socket_t *sock)
{
	connection_pool_t *pool;
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

	pool = connection_pool_new();

	connection_pool_add_connection(pool, connection_new(&server_ops, sock));
	while (connection_pool_poll(pool))
		;

	sigprocmask(SIG_SETMASK, &omask, NULL);
}
