/*
 * twopence config command
 *
 * Copyright (C) 2015 SUSE
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
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <ctype.h>

#include "twopence.h"

char *short_options = "f:h";
struct option long_options[] = {
  { "filename",	required_argument, NULL, 'f' },
  { "help",	no_argument, NULL, 'h' },
  { NULL }
};

static int	split_attr(char *nameattr, char **namep, char **valuep);

static void
show_usage(void)
{
	fprintf(stderr,
		"twopence config <subcommand> [--filename <path>] args ...\n"
		"\n"
		"Subcommands:\n"
		"  create name1=value name2=\"quoted-value\" ...\n"
		"     Create a new config file, optionally setting global attributes\n"
		"  set-attr name1=value name2=\"quoted-value\" ...\n"
		"     Explicitly set global attributes\n"
		"  get-attr name\n"
		"     Query a global attribute\n"
		"  add-target name spec [attr=value] ...\n"
		"     Add a named target, optionally setting target attributes\n"
		"  target-set-attr target-name name1=value name2=\"quoted-value\" ...\n"
		"     Explicitly set one ore more target attributes\n"
		"  target-get-attr target-name name\n"
		"     Query a target attribute\n"
		"  delete\n"
		"     Delete the config file\n"
		"  help\n"
		"     Display this help message\n"
		"\n"
		"The config file can be specified the the --filename option, or through the\n"
		"TWOPENCE_CONFIG_PATH environment variable. If neither is given, it will default\n"
		"to twopence.conf in the current working directory\n"
		"\n"
		"Typical global attributes might be the default user to run commands as,\n"
		"or a timeout value. Typical target attributes may be the target's hostname\n"
		"or its IP address.\n"
	       );
}

int
do_config(int argc, char **argv)
{
	twopence_config_t *cfg = NULL;
	char *opt_pathname = NULL;
	char *cmd;
	int c;

	argv++, argc--;
	if (argc <= 0) {
		show_usage();
		return 0;
	}

	cmd = argv[0];
	if (!strcmp(cmd, "help")) {
		show_usage();
		return 0;
	}

	while ((c = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
		switch (c) {
		case 'h':
			/* show usage */
			return 0;

		case 'f':
			opt_pathname = optarg;
			break;

		default:
			fprintf(stderr, "Unsupported option\n");
			/* show usage */
			return 1;
		}
	}

	if (opt_pathname == NULL) {
		opt_pathname = getenv("TWOPENCE_CONFIG_PATH");
		if (opt_pathname == NULL)
			opt_pathname = "twopence.conf";
	}

	if (!strcmp(cmd, "create")) {
		/* config add-target <name> <spec> [attr="value"] ... */
		cfg = twopence_config_new();

		while (optind < argc) {
			char *name, *value;

			if (!split_attr(argv[optind++], &name, &value))
				return 1;
			twopence_config_set_attr(cfg, name, value);
		}
	} else
	if (!strcmp(cmd, "delete")) {
		if (unlink(opt_pathname) < 0 && errno != ENOENT) {
			fprintf(stderr, "twopence: unable to delete config file \"%s\": %m\n", opt_pathname);
			return 1;
		}
		opt_pathname = NULL; /* don't re-write it */
	} else {
		cfg = twopence_config_read(opt_pathname);
		if (cfg == NULL) {
			fprintf(stderr, "twopence: unable to read config file \"%s\"\n", opt_pathname);
			return 1;
		}

		if (!strcmp(cmd, "add-target")) {
			twopence_target_config_t *tgt;
			char *name, *spec;

			if (optind + 2 > argc) {
				fprintf(stderr, "twopence config %s: missing argument(s)\n", cmd);
				show_usage();
				return 1;
			}
			name = argv[optind++];
			spec = argv[optind++];

			tgt = twopence_config_add_target(cfg, name, spec);
			if (tgt == NULL) {
				fprintf(stderr, "twopence config: unable to add target \"%s\"\n", name);
				return 1;
			}

			while (optind < argc) {
				char *name, *value;

				if (!split_attr(argv[optind++], &name, &value))
					return 1;
				twopence_target_config_set_attr(tgt, name, value);
			}
		} else
		if (!strcmp(cmd, "set-attr")) {
			while (optind < argc) {
				char *name, *value;

				if (!split_attr(argv[optind++], &name, &value))
					return 1;
				twopence_config_set_attr(cfg, name, value);
			}
		} else
		if (!strcmp(cmd, "get-attr")) {
			const char *value;

			if (optind + 1 != argc) {
				fprintf(stderr, "twopence config get-attr: bad number of arguments\n");
				return 1;
			}

			value = twopence_config_get_attr(cfg, argv[optind]);
			if (value)
				printf("%s\n", value);
			opt_pathname = NULL; /* No need to rewrite config file */
		} else
		if (!strcmp(cmd, "target-set-attr") || !strcmp(cmd, "target-get-attr")) {
			twopence_target_config_t *tgt;
			char *tgtname;

			if (optind >= argc) {
				fprintf(stderr, "twopence config %s: missing target name\n", cmd);
				return 1;
			}
			tgtname = argv[optind++];

			tgt = twopence_config_get_target(cfg, tgtname);
			if (tgt == NULL) {
				fprintf(stderr, "twopence config %s: no target named \"%s\"\n", cmd, tgtname);
				return 1;
			}

			if (!strcmp(cmd, "target-set-attr")) {
				while (optind < argc) {
					char *name, *value;

					if (!split_attr(argv[optind++], &name, &value))
						return 1;
					twopence_target_config_set_attr(tgt, name, value);
				}
			} else {
				const char *value;

				if (optind + 1 != argc) {
					fprintf(stderr, "twopence config get-attr: bad number of arguments\n");
					return 1;
				}

				value = twopence_target_config_get_attr(tgt, argv[optind]);
				if (value)
					printf("%s\n", value);
				opt_pathname = NULL; /* No need to rewrite config file */
			}
		} else {
			fprintf(stderr, "twopence config: unsupported subcommand \"%s\"\n", cmd);
			return 1;
		}
	}

	if (opt_pathname && twopence_config_write(cfg, opt_pathname) < 0) {
		fprintf(stderr, "twopence config %s: unable to rewrite config file\n", cmd);
		return 1;
	}

	return 0;
}

static int
__split_attr(char *s, char **namep, char **valuep)
{
	*namep = s;

	if (!isalpha(*s))
		return 0;
	while (isalnum(*s) || *s == '_')
		++s;
	if (*s != '=')
		return 0;
	*s++ = '\0';
	if (*s == '"') {
		int len;

		len = strlen(s);
		if (len < 2 || s[len-1] != '"')
			return 0;
		s[len-1] = '"';
		*valuep = s + 1;
	} else {
		*valuep = s;
	}
	return 1;
}

int
split_attr(char *nameattr, char **namep, char **valuep)
{
	char *s = strdup(nameattr);

	if (!__split_attr(nameattr, namep, valuep)) {
		fprintf(stderr, "Cannot parse attribute assignment %s\n", s);
		free(s);
		return 0;
	}

	free(s);
	return 1;
}
