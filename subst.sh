#!/bin/bash
#
# Replace version and date information in header files,
# manpages etc.
#

VERSION=0.3.5
DATE=$(LANG=C date "+%B %Y")

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
