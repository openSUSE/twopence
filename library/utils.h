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

typedef struct twopence_timeout {
	struct timeval		now;
	struct timeval		until;
} twopence_timeout_t;

extern void	twopence_timeout_init(twopence_timeout_t *);
extern bool	twopence_timeout_update(twopence_timeout_t *, const struct timeval *deadline);
extern long	twopence_timeout_msec(const twopence_timeout_t *);

#endif /* UTILS_H */
