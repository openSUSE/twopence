/*
 * Timer handling routines
 *
 * Copyright (C) 2014-2016 SUSE
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
#include <sys/time.h>

#include <errno.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include "utils.h"
#include "twopence.h"

static unsigned int		__global_timer_id = 1;
static twopence_timer_list_t	__global_timer_list;

/*
 * List helper functions
 */
static inline void
__twopence_timer_insert(twopence_timer_t **pos, twopence_timer_t *timer)
{
	timer->next = *pos;
	timer->prev = pos;
	*pos = timer;
}

static inline void
__twopence_timer_unlink(twopence_timer_t *timer)
{
	twopence_timer_t **pos, *next;

	next = timer->next;
	if ((pos = timer->prev) != NULL) {
		*pos = next;
		if (next)
			next->prev = pos;

		timer->prev = NULL;
		timer->next = NULL;
	}
}


int
twopence_timer_create(unsigned long timeout_ms, twopence_timer_t **timer_ret)
{
	struct timeval now;
	twopence_timer_t *timer;

	timer = twopence_calloc(1, sizeof(*timer));
	timer->refcount = 1;
	timer->id = __global_timer_id++;

	gettimeofday(&now, NULL);
	timer->runtime.tv_sec = timeout_ms / 1000;
	timer->runtime.tv_usec = (timeout_ms % 1000) * 1000;
	timeradd(&now, &timer->runtime, &timer->expires);

	timer->state = TWOPENCE_TIMER_STATE_ACTIVE;
	twopence_timer_list_insert(&__global_timer_list, timer);

	twopence_debug("Created timer %u", timer->id);
	*timer_ret = timer;

	return 0;
}

void
twopence_timer_set_callback(twopence_timer_t *timer, void (*callback)(twopence_timer_t *, void *), void *user_data)
{
	timer->callback = callback;
	timer->user_data = user_data;
}

static void
__twopence_timer_free(twopence_timer_t *timer)
{
	assert(timer->prev == NULL);
	free(timer);
}

void
twopence_timer_hold(twopence_timer_t *timer)
{
	assert(timer->refcount);
	timer->refcount ++;
}

void
twopence_timer_release(twopence_timer_t *timer)
{
	assert(timer->refcount);
	if (--(timer->refcount) == 0)
		__twopence_timer_free(timer);
}

void
twopence_timer_cancel(twopence_timer_t *timer)
{
	if (timer->state == TWOPENCE_TIMER_STATE_ACTIVE
	 || timer->state == TWOPENCE_TIMER_STATE_PAUSED
	 || timer->state == TWOPENCE_TIMER_STATE_CANCELLED) {
		timer->state = TWOPENCE_TIMER_STATE_CANCELLED;
		__twopence_timer_unlink(timer);
	}
}

void
twopence_timer_pause(twopence_timer_t *timer)
{
	/* silently ignore duplicate calls to pause a timer */
	if (timer->state == TWOPENCE_TIMER_STATE_PAUSED)
		return;

	if (timer->state == TWOPENCE_TIMER_STATE_ACTIVE) {
		struct timeval now;

		gettimeofday(&now, NULL);
		if (timercmp(&now, &timer->expires, <))
			timersub(&timer->expires, &now, &timer->runtime);
		else
			timerclear(&timer->runtime);
		timerclear(&timer->expires);

		timer->state = TWOPENCE_TIMER_STATE_PAUSED;
	}
}

void
twopence_timer_unpause(twopence_timer_t *timer)
{
	if (timer->state == TWOPENCE_TIMER_STATE_PAUSED) {
		struct timeval now;

		gettimeofday(&now, NULL);
		timeradd(&timer->runtime, &now, &timer->expires);
		timer->state = TWOPENCE_TIMER_STATE_ACTIVE;
	}
}

long
twopence_timer_remaining(const twopence_timer_t *timer)
{
	struct timeval now, delta;

	switch (timer->state) {
	case TWOPENCE_TIMER_STATE_ACTIVE:
		gettimeofday(&now, NULL);
		if (timercmp(&now, &timer->expires, <)) {
			timersub(&timer->expires, &now, &delta);
			return 1000 * delta.tv_sec + delta.tv_usec / 1000;
		}

		return 0;

	default:
		return 0;
	}
}

void
twopence_timer_kill(twopence_timer_t *timer)
{
	timer->state = TWOPENCE_TIMER_STATE_DEAD;
	timer->callback = NULL;

	__twopence_timer_unlink(timer);
	twopence_timer_release(timer);
}

static void
__twopence_timer_mark_expired(twopence_timer_t *timer)
{
	twopence_debug("Timer %u expired", timer->id);
	timer->state = TWOPENCE_TIMER_STATE_EXPIRED;
	timerclear(&timer->expires);

	/* Do /not/ invoke the callback yet - we may be deep inside
	 * some transport code, which may or may not be re-entrant.
	 * We do this at a later point, from twopence_timer_list_reap()
	 */
}

void
twopence_timer_list_insert(twopence_timer_list_t *list, twopence_timer_t *timer)
{
	assert(timerisset(&timer->expires));
	assert(timer->prev == NULL);
	__twopence_timer_insert(&list->head, timer);
}

void
twopence_timer_list_move(twopence_timer_list_t *list, twopence_timer_t *timer)
{
	__twopence_timer_unlink(timer);
	__twopence_timer_insert(&list->head, timer);
}

/*
 * Walk the list of timers, and update the twopence_timeout_t to reflect the
 * point in time when the next timer expires.
 * If a timer has already expired, this will result in a timeout of 0,
 * and the respective time is moved to state TWOPENCE_TIMER_STATE_EXPIRED.
 */
void
twopence_timer_list_update_timeout(twopence_timer_list_t *list, twopence_timeout_t *tmo)
{
	twopence_timer_t *t;

	for (t = list->head; t; t = t->next) {
		/* If the timer's expiry time is in the past,
		 * twopence_timeout_update() will return false
		 * and set tmo->expired = true;
		 */
		if (t->state == TWOPENCE_TIMER_STATE_ACTIVE
		 && !twopence_timeout_update(tmo, &t->expires))
			__twopence_timer_mark_expired(t);
	}
}

void
twopence_timer_list_expire(twopence_timer_list_t *list)
{
	twopence_timeout_t tmo;

	twopence_timeout_init(&tmo);
	twopence_timer_list_update_timeout(list, &tmo);
}

void
twopence_timer_list_reap(twopence_timer_list_t *list, twopence_timer_list_t *expired)
{
	twopence_timer_t *t, *next;

	for (t = list->head; t; t = next) {
		next = t->next;

		if (t->state == TWOPENCE_TIMER_STATE_EXPIRED
		 || t->state == TWOPENCE_TIMER_STATE_CANCELLED) {
			twopence_debug("Reaping timer %u (state %d)", t->id, t->state);
			twopence_timer_list_move(expired, t);
		}
	}
}

void
twopence_timer_list_invoke(twopence_timer_list_t *list)
{
	twopence_timer_t *t;

	while ((t = list->head) != NULL) {
		if (t->state == TWOPENCE_TIMER_STATE_EXPIRED && t->callback) {
			twopence_debug("Invoking timer %u", t->id);
			t->callback(t, t->user_data);
		}

		twopence_timer_kill(t);
	}
}


void
twopence_timer_list_destroy(twopence_timer_list_t *list)
{
	twopence_timer_t *t;

	while ((t = list->head) != NULL)
		twopence_timer_kill(t);
}

void
twopence_timers_update_timeout(twopence_timeout_t *tmo)
{
	twopence_timer_list_update_timeout(&__global_timer_list, tmo);
}

void
twopence_timers_run(void)
{
	twopence_timer_list_t expired = { .head = NULL };
	twopence_timeout_t timeout;

	/* Do another pass over the list, and catch timers that have
	 * expired since the last inspection.
	 *
	 * We do this because the usual approach is
	 *
	 *   twopence_timers_update_timeout(...);
	 *   poll(..)
	 *   twopence_timers_run();
	 *
	 * So we have to account for the fact that we spent some time
	 * inside poll()
	 */
	twopence_timeout_init(&timeout);
	twopence_timer_list_update_timeout(&__global_timer_list, &timeout);

	twopence_timer_list_reap(&__global_timer_list, &expired);
	twopence_timer_list_invoke(&expired);
	twopence_timer_list_destroy(&expired);
}
