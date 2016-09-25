require 'mkmf'

extension_name = 'twopence'
dir_config(extension_name)

# this are not needed for Fedora and co, since are from rpms env vars.
#FIXME: maybe detect wich OS is running and make this for openSUSE else not

# $LDFLAGS = ENV['LDFLAGS'] + ' ' + $LDFLAGS
# $CFLAGS = ENV['CFLAGS'] + ' ' + $CFLAGS
have_library('twopence', 'twopence_target_new')
create_makefile(extension_name)
