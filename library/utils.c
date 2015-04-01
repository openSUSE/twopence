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
#include "twopence.h"
#include "utils.h"

void
twopence_timeout_init(twopence_timeout_t *tmo)
{
	gettimeofday(&tmo->now, NULL);
	timerclear(&tmo->until);
}

bool
twopence_timeout_update(twopence_timeout_t *tmo, const struct timeval *deadline)
{
	struct timeval delta;

	if (deadline->tv_sec == 0)
		return true;

	if (timercmp(&tmo->now, deadline, >=))
		return false; /* expired */

	/* deadline is still in the future. Figure out how much longer we have */
	timersub(deadline, &tmo->now, &delta);
	if (!timerisset(&tmo->until) || timercmp(&delta, &tmo->until, <))
		tmo->until = delta;

	return true;
}

long
twopence_timeout_msec(const twopence_timeout_t *tmo)
{
	if (!timerisset(&tmo->until))
		return -1;
	return 1000 * tmo->until.tv_sec + tmo->until.tv_usec / 1000;
}

struct timespec *
twopence_timeout_timespec(const twopence_timeout_t *tmo)
{
	static struct timespec value;

	if (!timerisset(&tmo->until))
		return NULL;
	value.tv_sec = tmo->until.tv_sec;
	value.tv_nsec = tmo->until.tv_usec * 1000;
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
