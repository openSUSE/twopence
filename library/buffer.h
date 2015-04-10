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


#ifndef TWOPENCE_BUFFER_H
#define TWOPENCE_BUFFER_H

#include <stdint.h>
#include <stdbool.h>

typedef struct twopence_buf twopence_buf_t;

struct twopence_buf {
	char *		base;
	unsigned int	head;
	unsigned int	tail;
	unsigned int	size;
};

extern void		twopence_buf_init(twopence_buf_t *bp);
extern void		twopence_buf_init_static(twopence_buf_t *bp, void *data, size_t len);
extern void		twopence_buf_destroy(twopence_buf_t *bp);
extern twopence_buf_t *	twopence_buf_new(size_t max_size);
extern twopence_buf_t *	twopence_buf_clone(twopence_buf_t *bp);
extern void		twopence_buf_free(twopence_buf_t *bp);
extern const void *	twopence_buf_head(const twopence_buf_t *bp);
extern void *		twopence_buf_tail(const twopence_buf_t *bp);
extern unsigned int	twopence_buf_tailroom(const twopence_buf_t *bp);
extern unsigned int	twopence_buf_tailroom_max(const twopence_buf_t *bp);
extern unsigned int	twopence_buf_count(const twopence_buf_t *bp);
extern void *		twopence_buf_pull(twopence_buf_t *bp, unsigned int len);
extern bool		twopence_buf_push(twopence_buf_t *bp, void *data, unsigned int len);
extern bool		twopence_buf_resize(twopence_buf_t *bp, unsigned int want_size);
extern bool		twopence_buf_ensure_tailroom(twopence_buf_t *bp, unsigned int want_tailroom);
extern void		twopence_buf_reserve_head(twopence_buf_t *bp, unsigned int len);
extern void *		twopence_buf_reserve_tail(twopence_buf_t *bp, unsigned int len);
extern void		twopence_buf_advance_tail(twopence_buf_t *bp, unsigned int len);
extern void		twopence_buf_advance_head(twopence_buf_t *bp, unsigned int len);
extern void		twopence_buf_truncate(twopence_buf_t *bp, unsigned int len);
extern bool		twopence_buf_append(twopence_buf_t *bp, const void *data, unsigned int len);
extern bool		twopence_buf_get(twopence_buf_t *bp, void *data, unsigned int len);
extern bool		twopence_buf_puts(twopence_buf_t *bp, const char *s);
extern const char *	twopence_buf_gets(twopence_buf_t *bp);
extern void		twopence_buf_reset(twopence_buf_t *bp);
extern void		twopence_buf_compact(twopence_buf_t *bp);

#endif /* TWOPENCE_BUFFER_H */
