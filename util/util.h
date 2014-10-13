/*
Just the utility routines for Twopence.


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

#include "../library/twopence.h"

int target_plugin(const char *);
char *target_virtio_serial_filename(const char *);
char *target_ssh_hostname(const char *);
int target_ssh_port(const char *);

void *open_library(const char *filename);
void *get_function(void *handle, const char *symbol);

int print_error(int rc);
