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
const char *
twopence_protocol_packet_type_to_string(unsigned int type)
{
	static char descbuf[64];

	switch (type) {
	case TWOPENCE_PROTO_TYPE_HELLO:
		return "hello";
	case TWOPENCE_PROTO_TYPE_INJECT:
		return "inject";
	case TWOPENCE_PROTO_TYPE_EXTRACT:
		return "extract";
	case TWOPENCE_PROTO_TYPE_COMMAND:
		return "command";
	case TWOPENCE_PROTO_TYPE_QUIT:
		return "quit";
	case TWOPENCE_PROTO_TYPE_CHAN_DATA:
		return "data";
	case TWOPENCE_PROTO_TYPE_CHAN_EOF:
		return "eof";
	case TWOPENCE_PROTO_TYPE_INTR:
		return "intr";
	case TWOPENCE_PROTO_TYPE_MAJOR:
		return "major";
	case TWOPENCE_PROTO_TYPE_MINOR:
		return "minor";
	case TWOPENCE_PROTO_TYPE_TIMEOUT:
		return "timeout";
	case TWOPENCE_PROTO_TYPE_KEEPALIVE:
		return "keepalive";
	default:
		snprintf(descbuf, sizeof(descbuf), "trans-type-%d", type);
		return descbuf;
	}
}

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

static inline bool
__encode_u16(twopence_buf_t *bp, uint16_t word)
{
	word = htons(word);
	return twopence_buf_append(bp, &word, sizeof(word));
}

static inline bool
__decode_u16(twopence_buf_t *bp, uint16_t *word)
{
	if (!twopence_buf_get(bp, word, sizeof(*word)))
		return false;
	*word = ntohs(*word);
	return true;
}

static inline bool
__encode_u32(twopence_buf_t *bp, uint32_t word)
{
	word = htonl(word);
	return twopence_buf_append(bp, &word, sizeof(word));
}

static inline bool
__decode_u32(twopence_buf_t *bp, uint32_t *word)
{
	if (!twopence_buf_get(bp, word, sizeof(*word)))
		return false;
	*word = ntohl(*word);
	return true;
}

static inline bool
__encode_string(twopence_buf_t *bp, const char *s)
{
	if (s == 0)
		return false;
	return twopence_buf_puts(bp, s);
}

static inline const char *
__decode_string(twopence_buf_t *bp)
{
	return twopence_buf_gets(bp);
}

/*
 * Channel packets:
 *  CHANNEL_DATA:	sending data during a file transfer, or on any of the standard fds
 *			associated with a command
 *  CHANNEL_EOF:	indicating EOF on this channel
 *  CHANNEL_ERROR:	indicating an error on the indicated channel.
 */
twopence_buf_t *
twopence_protocol_build_data_header(twopence_buf_t *bp, twopence_protocol_state_t *ps, uint16_t channel_id)
{
	assert(bp->head == TWOPENCE_PROTO_HEADER_SIZE + 2);

	channel_id = htons(channel_id);

	/* This should go to buffer.c */
	bp->head -= 2;
	memcpy((void *) twopence_buf_head(bp), &channel_id, 2);

	twopence_protocol_push_header_ps(bp, ps, TWOPENCE_PROTO_TYPE_CHAN_DATA);
	return bp;
}

static inline twopence_buf_t *
twopence_protocol_build_uint32_packet(twopence_protocol_state_t *ps, unsigned char type, uint32_t value)
{
	twopence_buf_t *bp;

	bp = twopence_protocol_command_buffer_new();
	if (!__encode_u32(bp, value)) {
		twopence_buf_free(bp);
		return NULL;
	}
	twopence_protocol_push_header_ps(bp, ps, type);
	return bp;
}

static inline bool
twopence_protocol_dissect_uint32_packet(twopence_buf_t *payload, uint32_t *value_ret)
{
	return __decode_u32(payload, value_ret);
}

twopence_buf_t *
twopence_protocol_build_major_packet(twopence_protocol_state_t *ps, int status)
{
	return twopence_protocol_build_uint32_packet(ps, TWOPENCE_PROTO_TYPE_MAJOR, status);
}

bool
twopence_protocol_dissect_major_packet(twopence_buf_t *payload, int *status_ret)
{
	uint32_t status;

	if (!twopence_protocol_dissect_uint32_packet(payload, &status))
		return false;
	*status_ret = status;
	return true;
}

twopence_buf_t *
twopence_protocol_build_minor_packet(twopence_protocol_state_t *ps, int status)
{
	return twopence_protocol_build_uint32_packet(ps, TWOPENCE_PROTO_TYPE_MINOR, status);
}

bool
twopence_protocol_dissect_minor_packet(twopence_buf_t *payload, int *status_ret)
{
	uint32_t status;

	if (!twopence_protocol_dissect_uint32_packet(payload, &status))
		return false;
	*status_ret = status;
	return true;
}

twopence_buf_t *
twopence_protocol_build_eof_packet(twopence_protocol_state_t *ps, uint16_t channel)
{
	twopence_buf_t *bp;

	bp = twopence_protocol_command_buffer_new();
	__encode_u16(bp, channel);
	twopence_protocol_push_header_ps(bp, ps, TWOPENCE_PROTO_TYPE_CHAN_EOF);
	return bp;
}

bool
twopence_protocol_dissect_eof_packet(twopence_buf_t *bp, uint16_t *channel_ret)
{
	return __decode_u16(bp, channel_ret);
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

twopence_buf_t *
twopence_protocol_build_hello_packet(unsigned int cid, unsigned int keepalive_timeout)
{
	struct twopence_protocol_hello_pkt data;
	twopence_buf_t *bp;

	/* Allocate a large buffer with space reserved for the header */
	bp = twopence_protocol_command_buffer_new();

	memset(&data, 0, sizeof(data));
	data.vers_major = TWOPENCE_PROTOCOL_VERSMAJOR;
	data.vers_minor = TWOPENCE_PROTOCOL_VERSMINOR;
	data.keepalive = htons(keepalive_timeout);

	twopence_buf_append(bp, &data, sizeof(data));

	/* Finalize the header */
	__twopence_protocol_push_header(bp, TWOPENCE_PROTO_TYPE_HELLO, cid, 0);
	return bp;
}

bool
twopence_protocol_dissect_hello_packet(twopence_buf_t *payload, unsigned char *version, unsigned int *keepalive)
{
	struct twopence_protocol_hello_pkt data;

	if (!twopence_buf_get(payload, &data, sizeof(data)))
		return false;

	version[0] = data.vers_major;
	version[1] = data.vers_minor;
	*keepalive = ntohs(data.keepalive);
	return true;
}

twopence_buf_t *
twopence_protocol_build_inject_packet(const twopence_protocol_state_t *ps, const twopence_file_xfer_t *xfer)
{
	twopence_buf_t *bp;

	/* Allocate a large buffer with space reserved for the header */
	bp = twopence_protocol_command_buffer_new();

	if (!__encode_string(bp, xfer->user)
	 || !__encode_string(bp, xfer->remote.name)
	 || !__encode_u32(bp, xfer->remote.mode)) {
		twopence_buf_free(bp);
		return NULL;
	}

	/* Finalize the header */
	twopence_protocol_push_header_ps(bp, ps, TWOPENCE_PROTO_TYPE_INJECT);
	return bp;
}

bool
twopence_protocol_dissect_inject_packet(twopence_buf_t *payload, twopence_file_xfer_t *xfer)
{
	const char *user, *file;
	uint32_t mode;

	if (!(user = __decode_string(payload))
	 || !(file = __decode_string(payload))
	 || !__decode_u32(payload, &mode))
		return false;

	xfer->user = user;
	xfer->remote.name = file;
	xfer->remote.mode = mode;
	return true;
}

twopence_buf_t *
twopence_protocol_build_command_packet(const twopence_protocol_state_t *ps, const twopence_command_t *cmd)
{
	twopence_buf_t *bp;
	unsigned int i;

	/* Allocate a large buffer with space reserved for the header */
	bp = twopence_protocol_command_buffer_new();

	if (!__encode_string(bp, cmd->user)
	 || !__encode_string(bp, cmd->command)
	 || !__encode_u32(bp, cmd->timeout)
	 || !__encode_u32(bp, cmd->request_tty)
	 /* reserve two words for future extensions */
	 || !__encode_u32(bp, 0)
	 || !__encode_u32(bp, 0))
		goto failed;

	for (i = 0; i < cmd->env.count; ++i) {
		const char *var = cmd->env.array[i];

		twopence_debug("send env var %s", var);
		if (!__encode_string(bp, var))
			goto failed;
	}

	/* Finalize the header */
	twopence_protocol_push_header_ps(bp, ps, TWOPENCE_PROTO_TYPE_COMMAND);
	return bp;

failed:
	twopence_buf_free(bp);
	return NULL;
}

bool
twopence_protocol_dissect_command_packet(twopence_buf_t *payload, twopence_command_t *cmd)
{
	const char *user, *command, *envar;
	uint32_t timeout, request_tty, reserved;

	if (!(user = __decode_string(payload))
	 || !(command = __decode_string(payload))
	 || !__decode_u32(payload, &timeout)
	 || !__decode_u32(payload, &request_tty)
	 || !__decode_u32(payload, &reserved)
	 || !__decode_u32(payload, &reserved))
		return false;

	while ((envar = __decode_string(payload)) != NULL) {
		char *value;

		if (!(value = strchr(envar, '='))) {
			twopence_log_error("ignoring invalid environment variable \"%s\"", envar);
			continue;
		}
		*value++ = '\0';
		twopence_command_setenv(cmd, envar, value);
	}

	cmd->user = user;
	cmd->command = command;
	cmd->timeout = timeout;
	cmd->request_tty = !!request_tty;
	return true;
}

twopence_buf_t *
twopence_protocol_build_extract_packet(const twopence_protocol_state_t *ps, const twopence_file_xfer_t *xfer)
{
	twopence_buf_t *bp;

	/* Allocate a large buffer with space reserved for the header */
	bp = twopence_protocol_command_buffer_new();

	/* Format the arguments */
	if (!__encode_string(bp, xfer->user)
	 || !__encode_string(bp, xfer->remote.name)) {
		twopence_buf_free(bp);
		return NULL;
	}

	/* Finalize the header */
	twopence_protocol_push_header_ps(bp, ps, TWOPENCE_PROTO_TYPE_EXTRACT);
	return bp;
}

bool
twopence_protocol_dissect_extract_packet(twopence_buf_t *payload, twopence_file_xfer_t *xfer)
{
	const char *user, *file;

	if (!(user = __decode_string(payload))
	 || !(file = __decode_string(payload)))
		return false;

	xfer->user = user;
	xfer->remote.name = file;
	return true;
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
