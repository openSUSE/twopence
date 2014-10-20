Gem::Specification.new do |s|
  s.name    = "twopence"
  s.version = "0.1.8"
  s.summary = "Twopence test executor"
  s.author  = "SUSE"

  s.files = "ext/twopence/glue.c", "ext/library/twopence.h", "ext/twopence/util.c", "ext/twopence/util.h"
  s.extensions = "ext/twopence/extconf.rb"

  s.add_development_dependency "rake-compiler"
end
