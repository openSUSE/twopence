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

/*
 * Increase the major number whenever old clients
 * stop working with the updated server.
 * Increase the minor number whenever a new client
 * would stop working the the old server.
 */
#define TWOPENCE_PROTOCOL_VERSMAJOR	2
#define TWOPENCE_PROTOCOL_VERSMINOR	0

#define TWOPENCE_PROTOCOL_VERSION	((TWOPENCE_PROTOCOL_VERSMAJOR << 8) | TWOPENCE_PROTOCOL_VERSMINOR)

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
#define TWOPENCE_PROTO_TYPE_CHAN_DATA	'D'
#define TWOPENCE_PROTO_TYPE_CHAN_EOF	'E'
#define TWOPENCE_PROTO_TYPE_INTR	'I'
#define TWOPENCE_PROTO_TYPE_MAJOR	'M'
#define TWOPENCE_PROTO_TYPE_MINOR	'm'
#define TWOPENCE_PROTO_TYPE_TIMEOUT	'T'
#define TWOPENCE_PROTO_TYPE_KEEPALIVE	'K'

typedef struct twopence_protocol_state {
	uint16_t	cid;
	uint16_t	xid;
} twopence_protocol_state_t;

#define TWOPENCE_PROTO_DEFAULT_KEEPALIVE 60

struct twopence_protocol_hello_pkt {
	unsigned char	vers_major;
	unsigned char	vers_minor;
	uint16_t	keepalive;
} __attribute((packed));

extern const char *	twopence_protocol_packet_type_to_string(unsigned int type);
extern void		twopence_protocol_build_header(twopence_buf_t *bp, unsigned char type);
extern void		twopence_protocol_push_header(twopence_buf_t *bp, unsigned char type);
extern void		twopence_protocol_push_header_ps(twopence_buf_t *bp, const twopence_protocol_state_t *ps, unsigned char type);
extern twopence_buf_t *	twopence_protocol_command_buffer_new();
extern twopence_buf_t *	twopence_protocol_build_simple_packet(unsigned char type);
extern twopence_buf_t *	twopence_protocol_build_simple_packet_ps(twopence_protocol_state_t *, unsigned char);
extern twopence_buf_t *	twopence_protocol_build_major_packet(twopence_protocol_state_t *ps, int status);
extern twopence_buf_t *	twopence_protocol_build_minor_packet(twopence_protocol_state_t *ps, int status);
extern twopence_buf_t *	twopence_protocol_build_hello_packet(unsigned int cid, unsigned int keepalive_interval);
extern twopence_buf_t *	twopence_protocol_build_data_header(twopence_buf_t *, twopence_protocol_state_t *, uint16_t);
extern twopence_buf_t *	twopence_protocol_build_eof_packet(twopence_protocol_state_t *, uint16_t);
extern twopence_buf_t *	twopence_protocol_build_inject_packet(const twopence_protocol_state_t *ps, const twopence_file_xfer_t *);
extern twopence_buf_t *	twopence_protocol_build_extract_packet(const twopence_protocol_state_t *ps, const twopence_file_xfer_t *);
extern twopence_buf_t *	twopence_protocol_build_command_packet(const twopence_protocol_state_t *ps, const twopence_command_t *);
extern twopence_buf_t *	twopence_protocol_recv_buffer_new(void);
extern int		twopence_protocol_buffer_need_to_recv(const twopence_buf_t *bp);
extern bool		twopence_protocol_buffer_complete(const twopence_buf_t *bp);
extern const twopence_hdr_t *twopence_protocol_dissect(twopence_buf_t *bp, twopence_buf_t *payload);
extern const twopence_hdr_t *twopence_protocol_dissect_ps(twopence_buf_t *bp, twopence_buf_t *payload, twopence_protocol_state_t *ps);
extern bool		twopence_protocol_dissect_major_packet(twopence_buf_t *payload, int *status_ret);
extern bool		twopence_protocol_dissect_minor_packet(twopence_buf_t *payload, int *status_ret);
extern bool		twopence_protocol_dissect_hello_packet(twopence_buf_t *payload, unsigned char version[2], unsigned int *keepalive);
extern bool		twopence_protocol_dissect_inject_packet(twopence_buf_t *payload, twopence_file_xfer_t *xfer);
extern bool		twopence_protocol_dissect_extract_packet(twopence_buf_t *payload, twopence_file_xfer_t *xfer);
extern bool		twopence_protocol_dissect_command_packet(twopence_buf_t *payload, twopence_command_t *cmd);

#endif /* PROTOCOL_H */
