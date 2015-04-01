/*
 * Packet building and disassembly routines for the serial and
 * virtio protocol
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


#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include "twopence.h"

typedef struct header twopence_hdr_t;
struct header {
	unsigned char	type;
	unsigned char	pad;
	uint16_t	cid;		/* unique client ID assigned by server */
	uint16_t	xid;		/* unique transaction ID */
	uint16_t	len;
} __attribute((packed));
#define TWOPENCE_PROTO_HEADER_SIZE	sizeof(twopence_hdr_t)
#define TWOPENCE_PROTO_MAX_PACKET	32768
#define TWOPENCE_PROTO_MAX_PAYLOAD	(TWOPENCE_PROTO_MAX_PACKET - TWOPENCE_PROTO_HEADER_SIZE)

#define TWOPENCE_PROTO_TYPE_HELLO	'h'
#define TWOPENCE_PROTO_TYPE_INJECT	'i'
#define TWOPENCE_PROTO_TYPE_EXTRACT	'e'
#define TWOPENCE_PROTO_TYPE_COMMAND	'c'
#define TWOPENCE_PROTO_TYPE_QUIT	'q'
#define TWOPENCE_PROTO_TYPE_STDIN	'0'
#define TWOPENCE_PROTO_TYPE_STDOUT	'1'
#define TWOPENCE_PROTO_TYPE_STDERR	'2'
#define TWOPENCE_PROTO_TYPE_DATA	'd'
#define TWOPENCE_PROTO_TYPE_EOF		'E'
#define TWOPENCE_PROTO_TYPE_INTR	'I'
#define TWOPENCE_PROTO_TYPE_MAJOR	'M'
#define TWOPENCE_PROTO_TYPE_MINOR	'm'
#define TWOPENCE_PROTO_TYPE_TIMEOUT	'T'

extern void		twopence_protocol_build_header(twopence_buf_t *bp, unsigned char type);
extern void		twopence_protocol_push_header(twopence_buf_t *bp, unsigned char type);
extern twopence_buf_t *	twopence_protocol_command_buffer_new();
extern twopence_buf_t *	twopence_protocol_build_simple_packet(unsigned char type);
extern twopence_buf_t *	twopence_protocol_build_eof_packet(void);
extern twopence_buf_t *	twopence_protocol_build_hello_packet(unsigned int cid);
extern twopence_buf_t *	twopence_protocol_build_inject_packet(const char *user, const char *remote_name, unsigned int remote_mode);
extern twopence_buf_t *	twopence_protocol_build_extract_packet(const char *user, const char *remote_name);
extern twopence_buf_t *	twopence_protocol_build_command_packet(const char *user, const char *command, long timeout);
extern twopence_buf_t *	twopence_protocol_build_uint_packet(unsigned char type, unsigned int value);
extern twopence_buf_t *	twopence_protocol_recv_buffer_new(void);
extern int		twopence_protocol_buffer_need_to_recv(const twopence_buf_t *bp);
extern bool		twopence_protocol_buffer_complete(const twopence_buf_t *bp);
extern const twopence_hdr_t *twopence_protocol_dissect(twopence_buf_t *bp, twopence_buf_t *payload);
extern bool		twopence_protocol_dissect_string(twopence_buf_t *bp, char *stringbuf, unsigned int size);
extern bool		twopence_protocol_dissect_string_delim(twopence_buf_t *bp, char *stringbuf, unsigned int size, char delimiter);
extern bool		twopence_protocol_dissect_uint(twopence_buf_t *bp, unsigned int *retval);
extern bool		twopence_protocol_dissect_int(twopence_buf_t *bp, int *retval);

#endif /* PROTOCOL_H */
