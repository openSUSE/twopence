/*
Plugins for Twopence test executor ruby bindings - declarations.


Copyright (C) 2014 SUSE

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 2.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "util.h"
#include "twopence.h"

void end_plugin(struct twopence_plugin *self);
struct twopence_plugin *get_plugin(void *handle);

// Virtio plugin
extern struct twopence_plugin virtio_plugin;
int init_virtio_plugin();
void end_virtio_plugin();
void *init_virtio_handle(const char *target);

// Serial plugin
extern struct twopence_plugin serial_plugin;
int init_serial_plugin();
void end_serial_plugin();
void *init_serial_handle(const char *target);

// SSH plugin
extern struct twopence_plugin ssh_plugin;
int init_ssh_plugin();
void end_ssh_plugin();
void *init_ssh_handle(const char *target);
