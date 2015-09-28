#!/bin/bash
#
# Replace version and date information in header files,
# manpages etc.
#

#
# The following two variables control all occurences of the version
# and date string as they appear in manpages, ruby gems etc.
#
# Whenever you update the minor version or patch level of twopence,
# this is all you need to touch.
#
# If we ever bump the major version number, more manual work is
# required.
#
VERSION=0.3.5
DATE="September 2015"

# Special case
if [ $# -eq 1 -a "$1" = "--version" ]; then
	echo "$VERSION"
	exit 0
fi

SEDOPT=""

# If no arguments are given, act as a pipe command, otherwise
# edit files in-place using "sed -i"
if [ $# -ne 0 ]; then
	SEDOPT=-i
fi

exec sed $SEDOPT \
	-e "s:@VERSION@:$VERSION:g" \
	-e "s:@DATE@:$DATE:g" \
	"$@"
