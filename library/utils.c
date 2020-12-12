/*
twopence utility functions.

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

#include <sys/time.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>

#include "twopence.h"
#include "utils.h"

#ifndef HAVE_PPOLL
int
ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *ts, const sigset_t *sigmask)
{
    int timeout_ms;

    if (ts) {
        int tmp, tmp2;

        if (ts->tv_sec > INT_MAX/1000)
            timeout_ms = INT_MAX;
        else {
            tmp = (int)(ts->tv_sec * 1000);
            /* round up 1ns to 1ms to avoid excessive wakeups for <1ms sleep */
            tmp2 = (int)((ts->tv_nsec + 999999L) / (1000L * 1000L));
            if (INT_MAX - tmp < tmp2)
                timeout_ms = INT_MAX;
            else
                timeout_ms = (int)(tmp + tmp2);
        }
    }
    else
        timeout_ms = -1;

    return poll(fds, nfds, timeout_ms);
}
#endif

void
twopence_timeout_init(twopence_timeout_t *tmo)
{
	gettimeofday(&tmo->now, NULL);
	timerclear(&tmo->until);
}

bool
twopence_timeout_update(twopence_timeout_t *tmo, const struct timeval *deadline)
{
	if (deadline->tv_sec == 0)
		return true;

	if (timercmp(&tmo->now, deadline, >=)) {
		tmo->until = tmo->now;
		return false; /* expired */
	}

	if (!timerisset(&tmo->until) || timercmp(deadline, &tmo->until, <))
		tmo->until = *deadline;

	return true;
}

long
twopence_timeout_msec(const twopence_timeout_t *tmo)
{
	struct timeval delta;

	if (!timerisset(&tmo->until))
		return -1;

	timersub(&tmo->until, &tmo->now, &delta);
	return 1000 * delta.tv_sec + delta.tv_usec / 1000;
}

struct timespec *
twopence_timeout_timespec(const twopence_timeout_t *tmo)
{
	static struct timespec value;
	struct timeval delta;

	if (!timerisset(&tmo->until))
		return NULL;

	timersub(&tmo->until, &tmo->now, &delta);
	value.tv_sec = delta.tv_sec;
	value.tv_nsec = delta.tv_usec * 1000;

	return &value;
}

void
twopence_pollinfo_init(twopence_pollinfo_t *pinfo, struct pollfd *pfd_array, unsigned int max_fds)
{
	twopence_timeout_init(&pinfo->timeout);
	pinfo->pfd = pfd_array;
	pinfo->max_fds = max_fds;
	pinfo->num_fds = 0;
}

struct pollfd *
twopence_pollinfo_update(twopence_pollinfo_t *pinfo, int fd, int events, const struct timeval *deadline)
{
	struct pollfd *pfd;

	if (deadline && !twopence_timeout_update(&pinfo->timeout, deadline))
		return NULL;

	if (pinfo->num_fds >= pinfo->max_fds) {
		twopence_log_error("too many fds in pollinfo");
		return NULL;
	}

	pfd = pinfo->pfd + pinfo->num_fds++;
	pfd->events = events;
	pfd->fd = fd;

	return pfd;
}

int
twopence_pollinfo_poll(const twopence_pollinfo_t *pinfo)
{
	if (pinfo->num_fds == 0)
		twopence_debug("No events to wait for?!\n");
	return poll(pinfo->pfd, pinfo->num_fds, twopence_timeout_msec(&pinfo->timeout));
}

int
twopence_pollinfo_ppoll(const twopence_pollinfo_t *pinfo, const sigset_t *mask)
{
	if (pinfo->num_fds == 0)
		twopence_debug("No events to wait for?!\n");
	return ppoll(pinfo->pfd, pinfo->num_fds, twopence_timeout_timespec(&pinfo->timeout), mask);
}

/*
 * Convert a sigal name to a signal number recognized by our libc.
 */
int
twopence_name_to_signal(const char *signal_name)
{
  static const char *signames[NSIG] = {
	[SIGHUP] = "HUP",
	[SIGINT] = "INT",
	[SIGQUIT] = "QUIT",
	[SIGILL] = "ILL",
	[SIGTRAP] = "TRAP",
#ifndef __APPLE__
	[SIGABRT] = "ABRT",
	[SIGIOT] = "IOT",
#endif
	[SIGBUS] = "BUS",
	[SIGFPE] = "FPE",
	[SIGKILL] = "KILL",
	[SIGUSR1] = "USR1",
	[SIGSEGV] = "SEGV",
	[SIGUSR2] = "USR2",
	[SIGPIPE] = "PIPE",
	[SIGALRM] = "ALRM",
	[SIGTERM] = "TERM",
#ifndef __APPLE__
	[SIGSTKFLT] = "STKFLT",
#endif
	[SIGCHLD] = "CHLD",
	[SIGCONT] = "CONT",
	[SIGSTOP] = "STOP",
	[SIGTSTP] = "TSTP",
	[SIGTTIN] = "TTIN",
	[SIGTTOU] = "TTOU",
	[SIGURG] = "URG",
	[SIGXCPU] = "XCPU",
	[SIGXFSZ] = "XFSZ",
	[SIGVTALRM] = "VTALRM",
	[SIGPROF] = "PROF",
	[SIGWINCH] = "WINCH",
	[SIGIO] = "IO",
#ifndef __APPLE__
	[SIGPWR] = "PWR",
#endif
	[SIGSYS] = "SYS",
  };
  int signo;

  for (signo = 0; signo < NSIG; ++signo) {
    const char *name = signames[signo];

    if (name && !strcmp(name, signal_name))
      return signo;
  }

  return -1;
}

/*
 * Wrappers for malloc and friends, checking for allocation erros
 */
#define check_and_return(p) \
	do { \
		assert(p); \
		return p; \
	} while (0)

void *
twopence_malloc(size_t size)
{
  void *p;

  if (size == 0)
    return NULL;

  p = malloc(size);
  check_and_return(p);
}

void *
twopence_realloc(void *p, size_t size)
{
  if (p == NULL)
    return twopence_malloc(size);

  if (size == 0) {
    free(p);
    return NULL;
  }

  p = realloc(p, size);
  check_and_return(p);
}

void *
twopence_calloc(size_t nmemb, size_t size)
{
  void *p;

  if (size == 0 || nmemb == 0)
    return NULL;
  p = calloc(nmemb, size);
  check_and_return(p);
}

char *
twopence_strdup(const char *s)
{
  /* Note, strdup just crashes if s is NULL. We're not trying to be cleverer than that */
  char *p = strdup(s);

  check_and_return(p);
}

void
twopence_strfree(char **sp)
{
  if (*sp != NULL) {
	  free(*sp);
	  *sp = NULL;
  }
}

