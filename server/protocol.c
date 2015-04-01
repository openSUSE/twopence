/*
 * protocol and transaction routines for test server.
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


/*
 * Protocol handling functions
 */
void
protocol_build_header(twopence_buf_t *bp, unsigned char type)
{
	unsigned int len = twopence_buf_count(bp);
	header_t hdr;

	assert(len < 65536);

	hdr.type = type;
	hdr.pad = 0;
	hdr.len = htons(len);

	memcpy((void *) twopence_buf_head(bp), &hdr, TWOPENCE_PROTO_HEADER_SIZE);
}

void
protocol_push_header(twopence_buf_t *bp, unsigned char type)
{
	/* When we post buffers to the output streams of a command, for instance,
	 * we reserve the space needed for the header.
	 * When we get here, we want to use that space, so we need to
	 * change the head pointer back to the start of the buffer. */
	assert(bp->head == TWOPENCE_PROTO_HEADER_SIZE);
	bp->head = 0;

	protocol_build_header(bp, type);
}

twopence_buf_t *
protocol_command_buffer_new()
{
	twopence_buf_t *bp;

	bp = twopence_buf_new(TWOPENCE_PROTO_MAX_PACKET);
	twopence_buf_reserve_tail(bp, TWOPENCE_PROTO_HEADER_SIZE);

	/* Reserve head room */
	bp->head = bp->tail = TWOPENCE_PROTO_HEADER_SIZE;

	return bp;
}

twopence_buf_t *
protocol_build_eof_packet(void)
{
	twopence_buf_t *bp;

	bp = protocol_command_buffer_new();
	protocol_push_header(bp, PROTO_HDR_TYPE_EOF);
	return bp;
}

twopence_buf_t *
protocol_build_uint_packet(unsigned char type, unsigned int value)
{
	twopence_buf_t *bp;
	char string[32];

	bp = protocol_command_buffer_new();

	snprintf(string, sizeof(string), "%u", value);
	twopence_buf_puts(bp, string);

	protocol_push_header(bp, type);
	return bp;
}

twopence_buf_t *
protocol_recv_buffer_new(void)
{
	twopence_buf_t *bp;

	bp = twopence_buf_new(TWOPENCE_PROTO_MAX_PACKET);
	twopence_buf_reserve_tail(bp, TWOPENCE_PROTO_HEADER_SIZE);
	return bp;
}

bool
protocol_buffer_complete(const twopence_buf_t *bp)
{
	const header_t *hdr;
	unsigned int len;

	len = twopence_buf_count(bp);
	if (len < TWOPENCE_PROTO_HEADER_SIZE)
		return false;

	hdr = (header_t *) twopence_buf_head(bp);
	if (len < htons(hdr->len))
		return false;
	return true;
}

const header_t *
protocol_dissect(twopence_buf_t *bp, twopence_buf_t *payload)
{
	header_t *hdr;
	unsigned int len;

	if (!(hdr = twopence_buf_pull(bp, TWOPENCE_PROTO_HEADER_SIZE)))
		return NULL;

	len = ntohs(hdr->len);
	if (len < TWOPENCE_PROTO_HEADER_SIZE) {
		fprintf(stderr, "%s: invalid header, len=%u\n", __func__, len);
		return NULL;
	}

	len -= TWOPENCE_PROTO_HEADER_SIZE;
	if (twopence_buf_count(bp) < len) {
		fprintf(stderr, "%s: called on incomplete packet (payload: header %u buffer %u)\n",
				__func__, len, twopence_buf_count(bp));
		return NULL;
	}

	twopence_buf_init_static(payload, (void *) twopence_buf_head(bp), len);
	twopence_buf_advance_head(bp, len);
	return hdr;
}

bool
protocol_dissect_string(twopence_buf_t *bp, char *stringbuf, unsigned int size)
{
	unsigned int n, k, count;
	char *s;

	count = twopence_buf_count(bp);
	s = (char *) twopence_buf_head(bp);

	for (n = 0; n < count && isspace(s[n]); ++n)
		;

	for (k = 0; n < count && !isspace(s[n]); ++n) {
		if (k + 2 >= size)
			return false;
		stringbuf[k++] = s[n];
	}
	stringbuf[k] = '\0';

	for (; n < count && isspace(s[n]); ++n)
		;
	bp->head += n;

	TRACE("%s()=\"%s\"\n", __func__, stringbuf);
	return true;
}

bool
protocol_dissect_string_delim(twopence_buf_t *bp, char *stringbuf, unsigned int size, char delimiter)
{
	unsigned int n = 0, k, count;
	char *s;

	count = twopence_buf_count(bp);
	s = (char *) twopence_buf_head(bp);

	for (k = 0; n < count && s[n] != delimiter; ++n) {
		if (k + 2 >= size)
			return false;
		stringbuf[k++] = s[n];
	}
	stringbuf[k] = '\0';
	bp->head += n;

	return true;
}

bool
protocol_dissect_uint(twopence_buf_t *bp, unsigned int *retval)
{
	char buffer[32], *s;

	if (!protocol_dissect_string(bp, buffer, sizeof(buffer)))
		return false;

	*retval = strtoul(buffer, &s, 0);
	if (*s)
		return false;
	return true;
}
