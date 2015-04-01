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
#include <stdarg.h>
#include <assert.h>
#include <ctype.h>
#include <limits.h>

#include "protocol.h"


/*
 * Protocol handling functions
 */
void
__twopence_protocol_build_header(twopence_buf_t *bp, unsigned char type, unsigned int cid, unsigned int xid)
{
	unsigned int len = twopence_buf_count(bp);
	twopence_hdr_t hdr;

	assert(len < 65536);

	hdr.type = type;
	hdr.pad = 0;
	hdr.cid = htons(cid);
	hdr.xid = htons(xid);
	hdr.len = htons(len);

	memcpy((void *) twopence_buf_head(bp), &hdr, TWOPENCE_PROTO_HEADER_SIZE);
}

void
twopence_protocol_build_header(twopence_buf_t *bp, unsigned char type)
{
	__twopence_protocol_build_header(bp, type, 0, 0);
}

void
__twopence_protocol_push_header(twopence_buf_t *bp, unsigned char type, unsigned int cid, unsigned int xid)
{
	/* When we post buffers to the output streams of a command, for instance,
	 * we reserve the space needed for the header.
	 * When we get here, we want to use that space, so we need to
	 * change the head pointer back to the start of the buffer. */
	assert(bp->head == TWOPENCE_PROTO_HEADER_SIZE);
	bp->head = 0;

	__twopence_protocol_build_header(bp, type, cid, xid);
}

void
twopence_protocol_push_header(twopence_buf_t *bp, unsigned char type)
{
	__twopence_protocol_push_header(bp, type, 0, 0);
}

void
twopence_protocol_push_header_ps(twopence_buf_t *bp, const twopence_protocol_state_t *ps, unsigned char type)
{
	__twopence_protocol_push_header(bp, type, ps->cid, ps->xid);
}

twopence_buf_t *
twopence_protocol_command_buffer_new()
{
	twopence_buf_t *bp;

	bp = twopence_buf_new(TWOPENCE_PROTO_MAX_PACKET);
	twopence_buf_reserve_tail(bp, TWOPENCE_PROTO_HEADER_SIZE);

	/* Reserve head room */
	bp->head = bp->tail = TWOPENCE_PROTO_HEADER_SIZE;

	return bp;
}

twopence_buf_t *
twopence_protocol_build_simple_packet_ps(twopence_protocol_state_t *ps, unsigned char type)
{
	twopence_buf_t *bp;

	bp = twopence_protocol_command_buffer_new();
	if (ps)
		twopence_protocol_push_header_ps(bp, ps, type);
	else
		twopence_protocol_push_header(bp, type);
	return bp;
}

twopence_buf_t *
twopence_protocol_build_simple_packet(unsigned char type)
{
	return twopence_protocol_build_simple_packet_ps(NULL, type);
}

twopence_buf_t *
twopence_protocol_build_eof_packet(twopence_protocol_state_t *ps)
{
	return twopence_protocol_build_simple_packet(TWOPENCE_PROTO_TYPE_EOF);
}

twopence_buf_t *
twopence_protocol_build_uint_packet(unsigned char type, unsigned int value)
{
	twopence_buf_t *bp;
	char string[32];

	bp = twopence_protocol_command_buffer_new();

	snprintf(string, sizeof(string), "%u", value);
	twopence_buf_puts(bp, string);

	twopence_protocol_push_header(bp, type);
	return bp;
}

twopence_buf_t *
twopence_protocol_build_uint_packet_ps(const twopence_protocol_state_t *ps, unsigned char type, unsigned int value)
{
	twopence_buf_t *bp;
	char string[32];

	bp = twopence_protocol_command_buffer_new();

	snprintf(string, sizeof(string), "%u", value);
	twopence_buf_puts(bp, string);

	twopence_protocol_push_header_ps(bp, ps, type);
	return bp;
}

static void
twopence_protocol_format_args(twopence_buf_t *bp, const char *fmt, ...)
{
	char string[8192];
	va_list ap;

	va_start(ap, fmt);

	vsnprintf(string, sizeof(string), fmt, ap);
	twopence_buf_puts(bp, string);

	va_end(ap);
}

twopence_buf_t *
twopence_protocol_build_hello_packet(unsigned int cid)
{
	twopence_buf_t *bp;

	/* Allocate a large buffer with space reserved for the header */
	bp = twopence_protocol_command_buffer_new();

	/* Finalize the header */
	__twopence_protocol_push_header(bp, TWOPENCE_PROTO_TYPE_HELLO, cid, 0);
	return bp;
}

twopence_buf_t *
twopence_protocol_build_inject_packet(const char *user, const char *remote_name, unsigned int remote_mode)
{
	twopence_buf_t *bp;

	/* Allocate a large buffer with space reserved for the header */
	bp = twopence_protocol_command_buffer_new();

	/* Format the arguments */
	twopence_protocol_format_args(bp, "%s %d %s", user, remote_mode, remote_name);

	/* Finalize the header */
	twopence_protocol_push_header(bp, TWOPENCE_PROTO_TYPE_INJECT);
	return bp;
}

twopence_buf_t *
twopence_protocol_build_command_packet(const twopence_protocol_state_t *ps, const char *user, const char *command, long timeout)
{
	twopence_buf_t *bp;

	/* Allocate a large buffer with space reserved for the header */
	bp = twopence_protocol_command_buffer_new();

	/* Format the arguments */
	twopence_protocol_format_args(bp, "%s %ld %s", user, timeout, command);

	/* Finalize the header */
	twopence_protocol_push_header_ps(bp, ps, TWOPENCE_PROTO_TYPE_COMMAND);

	return bp;
}

twopence_buf_t *
twopence_protocol_build_extract_packet(const char *user, const char *remote_name)
{
	twopence_buf_t *bp;

	/* Allocate a large buffer with space reserved for the header */
	bp = twopence_protocol_command_buffer_new();

	/* Format the arguments */
	twopence_protocol_format_args(bp, "%s %s", user, remote_name);

	/* Finalize the header */
	twopence_protocol_push_header(bp, TWOPENCE_PROTO_TYPE_EXTRACT);
	return bp;
}

twopence_buf_t *
twopence_protocol_recv_buffer_new(void)
{
	twopence_buf_t *bp;

	bp = twopence_buf_new(TWOPENCE_PROTO_MAX_PACKET);
	twopence_buf_reserve_tail(bp, TWOPENCE_PROTO_HEADER_SIZE);
	return bp;
}

int
twopence_protocol_buffer_need_to_recv(const twopence_buf_t *bp)
{
	const twopence_hdr_t *hdr;
	unsigned int len, total;

	len = twopence_buf_count(bp);
	if (len < TWOPENCE_PROTO_HEADER_SIZE)
		return TWOPENCE_PROTO_HEADER_SIZE - len;

	hdr = (twopence_hdr_t *) twopence_buf_head(bp);
	total = htons(hdr->len);
	if (total < TWOPENCE_PROTO_HEADER_SIZE)
		return -1;

	if (len < total)
		return total - len;

	return 0;
}

bool
twopence_protocol_buffer_complete(const twopence_buf_t *bp)
{
	return twopence_protocol_buffer_need_to_recv(bp) == 0;
}

const twopence_hdr_t *
twopence_protocol_dissect(twopence_buf_t *bp, twopence_buf_t *payload)
{
	twopence_hdr_t *hdr;
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

const twopence_hdr_t *
twopence_protocol_dissect_ps(twopence_buf_t *bp, twopence_buf_t *payload, twopence_protocol_state_t *ps)
{
	const twopence_hdr_t *hdr;

	if ((hdr = twopence_protocol_dissect(bp, payload)) == NULL)
		return hdr;

	ps->cid = ntohs(hdr->cid);
	ps->xid = ntohs(hdr->xid);
	return hdr;
}

bool
twopence_protocol_dissect_string(twopence_buf_t *bp, char *stringbuf, unsigned int size)
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

	return true;
}

bool
twopence_protocol_dissect_string_delim(twopence_buf_t *bp, char *stringbuf, unsigned int size, char delimiter)
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
twopence_protocol_dissect_uint(twopence_buf_t *bp, unsigned int *retval)
{
	char buffer[32], *s;

	if (!twopence_protocol_dissect_string(bp, buffer, sizeof(buffer)))
		return false;

	*retval = strtoul(buffer, &s, 0);
	if (*s)
		return false;
	return true;
}

bool
twopence_protocol_dissect_int(twopence_buf_t *bp, int *retval)
{
	char buffer[32], *s;

	if (!twopence_protocol_dissect_string(bp, buffer, sizeof(buffer)))
		return false;

	*retval = strtol(buffer, &s, 0);
	if (*s)
		return false;
	return true;
}
