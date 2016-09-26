require 'mkmf'

extension_name = 'twopence'
dir_config(extension_name)

$LDFLAGS = ENV['LDFLAGS'] + ' ' + $LDFLAGS
$CFLAGS = ENV['CFLAGS'] + ' ' + $CFLAGS
have_library('twopence', 'twopence_target_new') or raise
create_makefile(extension_name)
