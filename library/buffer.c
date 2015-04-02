/*
 * Twopence buffer routines
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
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "buffer.h"
#include "utils.h"

void
twopence_buf_init(twopence_buf_t *bp)
{
	memset(bp, 0, sizeof(*bp));
}

void
twopence_buf_init_static(twopence_buf_t *bp, void *data, size_t len)
{
	memset(bp, 0, sizeof(*bp));
	bp->base = data;
	bp->tail = len;
}

void
twopence_buf_destroy(twopence_buf_t *bp)
{
	twopence_buf_init(bp);
}

twopence_buf_t *
twopence_buf_new(size_t size)
{
	twopence_buf_t *bp;

	bp = twopence_calloc(1, sizeof(*bp) + size);
	bp->base = (char *)(bp + 1);
	bp->size = size;
	return bp;
}

twopence_buf_t *
twopence_buf_clone(twopence_buf_t *bp)
{
	unsigned int count = bp->tail - bp->head;
	twopence_buf_t *clone;

	clone = twopence_buf_new(count);
	twopence_buf_append(clone, bp->base + bp->head, count);
	return clone;
}

void
twopence_buf_free(twopence_buf_t *bp)
{
	twopence_buf_destroy(bp);
	free(bp);
}

const void *
twopence_buf_head(const twopence_buf_t *bp)
{
	return bp->base + bp->head;
}

void *
twopence_buf_tail(const twopence_buf_t *bp)
{
	return bp->base + bp->tail;
}

unsigned int
twopence_buf_tailroom(const twopence_buf_t *bp)
{
	return bp->size - bp->tail;
}

unsigned int
twopence_buf_tailroom_max(const twopence_buf_t *bp)
{
	return bp->size - bp->tail;
}

unsigned int
twopence_buf_count(const twopence_buf_t *bp)
{
	return bp->tail - bp->head;
}

void *
twopence_buf_pull(twopence_buf_t *bp, unsigned int len)
{
	void *h = bp->base + bp->head;

	if (twopence_buf_count(bp) < len)
		return NULL;
	bp->head += len;
	return h;
}

bool
twopence_buf_push(twopence_buf_t *bp, void *data, unsigned int len)
{
	if (bp->head < len)
		return false;
	bp->head -= len;
	memcpy(bp->base + bp->head, data, len);
	return true;
}

bool
twopence_buf_resize(twopence_buf_t *bp, unsigned int want_size)
{
	static const unsigned int BUFFER_MIN_SIZE = 128;
	static const unsigned int BUFFER_BIG_SIZE = 128 * 1024;
	unsigned int new_size;

	if (want_size <= bp->size)
		return true;

	if (want_size < BUFFER_MIN_SIZE) {
		new_size = BUFFER_MIN_SIZE;
	} else
	if (want_size < BUFFER_BIG_SIZE) {
		for (new_size = BUFFER_MIN_SIZE; new_size < want_size; new_size *= 2)
			;
	} else {
		new_size = want_size;
	}

	assert(want_size <= new_size);

	bp->base = twopence_realloc(bp->base, new_size);
	assert(bp->base);

	bp->size = new_size;
	return true;
}

bool
twopence_buf_ensure_tailroom(twopence_buf_t *bp, unsigned int want_tailroom)
{
	unsigned int tailroom;

	tailroom = twopence_buf_tailroom(bp);
	if (tailroom < want_tailroom) {
		twopence_buf_resize(bp, bp->tail + want_tailroom);
	}
	return true;
}

void
twopence_buf_reserve_head(twopence_buf_t *bp, unsigned int amount)
{
	assert(bp->head == bp->tail && bp->size > amount);
	bp->head = bp->tail = amount;
}

void *
twopence_buf_reserve_tail(twopence_buf_t *bp, unsigned int len)
{
	if (twopence_buf_tailroom(bp) < len)
		return NULL;

	return bp->base + bp->tail;
}

void
twopence_buf_advance_tail(twopence_buf_t *bp, unsigned int len)
{
	assert(twopence_buf_tailroom(bp) >= len);
	bp->tail += len;
}

void
twopence_buf_advance_head(twopence_buf_t *bp, unsigned int len)
{
	assert(twopence_buf_count(bp) >= len);
	bp->head += len;
}

void
twopence_buf_truncate(twopence_buf_t *bp, unsigned int len)
{
	if (len < twopence_buf_count(bp))
		bp->tail = bp->head + len;
}

bool
twopence_buf_append(twopence_buf_t *bp, const void *data, unsigned int len)
{
	if (!twopence_buf_reserve_tail(bp, len))
		return false;

	memcpy(bp->base + bp->tail, data, len);
	bp->tail += len;
	return true;
}

bool
twopence_buf_puts(twopence_buf_t *bp, const char *s)
{
	if (!s)
		return true;
	return twopence_buf_append(bp, s, strlen(s) + 1);
}

void
twopence_buf_reset(twopence_buf_t *bp)
{
	assert(twopence_buf_count(bp) == 0);
	bp->head = bp->tail = 0;
}

void
twopence_buf_compact(twopence_buf_t *bp)
{
	unsigned int count = twopence_buf_count(bp);

	if (count)
		memmove(bp->base, bp->base + bp->head, count);
	bp->head = 0;
	bp->tail = count;
}
