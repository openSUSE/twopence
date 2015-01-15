require 'mkmf'

extension_name = 'twopence'
dir_config(extension_name)
have_library('twopence', 'twopence_target_new')
create_makefile(extension_name)
