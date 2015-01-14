/*
 * twopence main command
 *
 * Used to drive one or more SUTs
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "twopence.h"

static void	show_usage(int rv);

extern int	do_config(int argc, char **argv);

int
main(int argc, char *argv[])
{
	char *cmd;
	int rv;

	if (argc <= 1)
		show_usage(0);

	cmd = argv[1];
	if (!strcmp(cmd, "help"))
		show_usage(0);

	if (!strcmp(cmd, "config")) {
		rv = do_config(argc - 1, argv + 1);
	} else {
		fprintf(stderr, "unsupported command \"%s\"\n", cmd);
		show_usage(1);
	}

	return rv;
}

void
show_usage(int rv)
{
	FILE *fp = rv? stderr : stdout;

	fprintf(fp,
		"Usage:\n"
		"twopence command [args]\n"
		"Currently supported commands:\n"
		"  config    modifiy the list of targets for a twopence test run\n"
		"  help      show this help message\n"
	       );
	exit(rv);
}
