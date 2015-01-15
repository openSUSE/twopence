/*
Definitions for twopence shell wrappers.


Copyright (C) 2014-2015 SUSE

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

// Return codes
#define RC_OK                     0

#define RC_INVALID_PARAMETERS     1
#define RC_LIBRARY_INIT_ERROR     2

#define RC_SIGNAL_HANDLER_ERROR   3
#define RC_ABORTED_BY_USER        4

#define RC_EXIT_REMOTE_ERROR      5
#define RC_INJECT_FILE_ERROR      6
#define RC_EXTRACT_FILE_ERROR     7
#define RC_EXEC_COMMAND_ERROR     8

#define RC_REMOTE_COMMAND_FAILED  9
#define RC_WRITE_RESULTS_ERROR   10
