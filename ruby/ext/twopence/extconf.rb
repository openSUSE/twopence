require 'mkmf'

extension_name = 'twopence'
dir_config(extension_name)
have_library('ssh', 'ssh_new');
create_makefile(extension_name)
