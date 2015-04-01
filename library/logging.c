/*
Logging utilities for twopence

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

#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <syslog.h>

#include "twopence.h"

static bool	twopence_log_initialized = false;
static FILE *	twopence_log_file;
static bool	twopence_log_syslog;

unsigned int	twopence_debug_level = 0;

void
twopence_logging_init()
{
  if (!twopence_log_initialized) {
    twopence_log_file = stderr;
    twopence_log_initialized = true;
  }
}

void
twopence_set_logfile(FILE *fp)
{
  twopence_log_file = fp;
  twopence_log_initialized = true;
}

void
twopence_set_syslog(bool on)
{
  twopence_log_syslog = on;
  twopence_log_initialized = true;
}

void
twopence_trace(const char *fmt, ...)
{
  va_list ap;

  if (!twopence_log_initialized)
    twopence_logging_init();

  va_start(ap, fmt);
  if (twopence_log_file) {
    vfprintf(twopence_log_file, fmt, ap);
  }
  if (twopence_log_syslog) {
    vsyslog(LOG_DEBUG, fmt, ap);
  }
}

void
twopence_log_error(const char *fmt, ...)
{
  va_list ap;

  if (!twopence_log_initialized)
    twopence_logging_init();

  va_start(ap, fmt);
  if (twopence_log_file) {
    fprintf(twopence_log_file, "Error: ");
    vfprintf(twopence_log_file, fmt, ap);
  }
  if (twopence_log_syslog) {
    vsyslog(LOG_ERR, fmt, ap);
  }
}
