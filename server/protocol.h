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

typedef struct header header_t;
struct header {
	unsigned char	type;
	unsigned char	pad;
	uint16_t	len;
};
#define TWOPENCE_PROTO_HEADER_SIZE	4
#define TWOPENCE_PROTO_MAX_PACKET	32768
#define TWOPENCE_PROTO_MAX_PAYLOAD	(TWOPENCE_PROTO_MAX_PACKET - TWOPENCE_PROTO_HEADER_SIZE)

#define PROTO_HDR_TYPE_INJECT	'i'
#define PROTO_HDR_TYPE_EXTRACT	'e'
#define PROTO_HDR_TYPE_COMMAND	'c'
#define PROTO_HDR_TYPE_QUIT	'q'
#define PROTO_HDR_TYPE_STDIN	'0'
#define PROTO_HDR_TYPE_STDOUT	'1'
#define PROTO_HDR_TYPE_STDERR	'2'
#define PROTO_HDR_TYPE_DATA	'd'
#define PROTO_HDR_TYPE_EOF	'E'
#define PROTO_HDR_TYPE_INTR	'I'
#define PROTO_HDR_TYPE_MAJOR	'M'
#define PROTO_HDR_TYPE_MINOR	'm'
#define PROTO_HDR_TYPE_TIMEOUT	'T'

extern void		protocol_build_header(twopence_buf_t *bp, unsigned char type);
extern void		protocol_push_header(twopence_buf_t *bp, unsigned char type);
extern twopence_buf_t *	protocol_command_buffer_new();
extern twopence_buf_t *	protocol_build_eof_packet(void);
extern twopence_buf_t *	protocol_build_uint_packet(unsigned char type, unsigned int value);
extern twopence_buf_t *	protocol_recv_buffer_new(void);
extern bool		protocol_buffer_complete(const twopence_buf_t *bp);
extern const header_t *	protocol_dissect(twopence_buf_t *bp, twopence_buf_t *payload);
extern bool		protocol_dissect_string(twopence_buf_t *bp, char *stringbuf, unsigned int size);
extern bool		protocol_dissect_string_delim(twopence_buf_t *bp, char *stringbuf, unsigned int size, char delimiter);
extern bool		protocol_dissect_uint(twopence_buf_t *bp, unsigned int *retval);

#endif /* PROTOCOL_H */
