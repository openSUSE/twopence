#!/bin/bash
#
# Install a manpage and replace some place holders in the .TH header line
#
# Copyright (C) 2015 Olaf Kirch <okir@suse.de>
#

MANDIR=/usr/share/man

function usage {

	echo "$@"
	echo "Usage: $0 [-d destdir] [-n instname] [-p instprefix] [-z] manpage" >&2
	exit 1
}

# Find the directory in which this script resides.
# The subst.sh script is expected to be in the same
# place.
utildir=${0%/*}

opt_compress=false
while getopts "d:n:p:v:z" arg; do
	case $arg in
	d)	opt_destdir=$OPTARG;;
	n)	opt_instname=$OPTARG;;
	p)	opt_prefix=$OPTARG;;
	z)	opt_compress=true;;
	*)	usage "Unexpected option -$arg";;
	esac
done
shift $(($OPTIND-1))

if [ $# -eq 0 ]; then
	usage "Missing manual page argument"
fi

if [ $# -gt 1 -a -n "$opt_instname" ]; then
	usage "Cannot install several manpages while using -n option"
fi

if $opt_compress; then
	suffix=".gz"
else
	suffix=""
fi

install_date=$(LANG=C date "+%B %Y")
for manpage; do
	basename=${manpage##*/}
	if [ -n "$opt_instname" ]; then
		instname=$opt_instname
	else
		instname="${opt_prefix}${basename}"
	fi

	mancat=${instname#*.}
	mancat=${mancat:0:1}

	case $mancat in
	1|2|3|4|5|6|7|8|9)
		# echo category $mancat
		: ;;
	*)
		echo "Unknown or unsupported manpage category" >&2
		exit 1;;
	esac

	destdir="$opt_destdir$MANDIR/man${mancat}"
	destfile="${destdir}/$instname"

	echo "Installing $manpage as $destfile$suffix"

	install -m 755 -d "$destdir"
	install -m 644 "$manpage" "$destfile"
	${utildir}/subst.sh $destfile

	$opt_compress && gzip -9f "$destfile"
done

exit 0
