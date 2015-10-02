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

#ifndef UTILS_H
#define UTILS_H

#include <sys/types.h>
#include <stdbool.h>
#include <poll.h>

typedef struct twopence_timeout {
	struct timeval		now;
	struct timeval		until;
} twopence_timeout_t;

typedef struct twopence_pollinfo {
	unsigned int		max_fds, num_fds;
	struct pollfd *		pfd;

	twopence_timeout_t	timeout;
} twopence_pollinfo_t;

extern void		twopence_timeout_init(twopence_timeout_t *);
extern bool		twopence_timeout_update(twopence_timeout_t *, const struct timeval *deadline);
extern long		twopence_timeout_msec(const twopence_timeout_t *);

extern void		twopence_pollinfo_init(twopence_pollinfo_t *, struct pollfd *, unsigned int);
extern struct pollfd *	twopence_pollinfo_update(twopence_pollinfo_t *, int fd, int events, const struct timeval *deadline);
extern int		twopence_pollinfo_poll(const twopence_pollinfo_t *);
extern int		twopence_pollinfo_ppoll(const twopence_pollinfo_t *, const sigset_t *);

extern int		twopence_name_to_signal(const char *signal_name);

extern void *		twopence_malloc(size_t size);
extern void *		twopence_realloc(void *p, size_t size);
extern void *		twopence_calloc(size_t nmemb, size_t size);
extern char *		twopence_strdup(const char *s);
extern void		twopence_strfree(char **sp);

#endif /* UTILS_H */
