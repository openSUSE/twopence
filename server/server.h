/*
 * I/O routines for test server.
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


#ifndef SERVER_H
#define SERVER_H

#include <stdint.h>
#include "twopence.h"
#include "connection.h"

#define DEFAULT_COMMAND_TIMEOUT	12	/* seconds */

extern void		server_run(twopence_sock_t *);
extern void		server_listen(twopence_sock_t *);

#define AUDIT(fmt, args...) \
	do { \
		if (server_audit) { \
			twopence_trace("%5u: " fmt, server_audit_seq++, ##args); \
		} else { \
			twopence_debug("AUDIT %5u: " fmt, server_audit_seq++, ##args); \
		} \
	} while (0)

extern unsigned int	twopence_debug_level;

extern bool		server_audit;
extern unsigned int	server_audit_seq;

#endif /* SERVER_H */
