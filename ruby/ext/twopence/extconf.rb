require 'mkmf'

extension_name = 'twopence'
dir_config(extension_name, '/usr/include/' , '/usr/lib/x86_64-linux-gnu')

# this are not needed for Fedora and co, since are from rpms env vars.
#FIXME: maybe detect wich OS is running and make this for openSUSE else not

# $LDFLAGS = '/usr/lib64/libtwopence.so' + ' '  + $LDFLAGS
# $CFLAGS = ENV['CFLAGS'] + ' ' + $CFLAGS

have_library('twopence', 'twopence_target_new') or raise "Requirements library not satisfied"
create_makefile(extension_name)
