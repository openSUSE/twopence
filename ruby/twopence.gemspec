Gem::Specification.new do |s|
  s.name    = "twopence"
  s.version = "0.1.8"
  s.summary = "Twopence test executor"
  s.description = "A test executor that can run tests in a KVM virtual machine without using the network, or that can run more traditional tests in a remote machine through SSH or serial lines."
  s.author  = "SUSE"
  s.homepage = "http://www.suse.com"
  s.license = "GPL-2"

  s.files = "ext/twopence/glue.c", "ext/twopence/plugins.h", "ext/twopence/plugins.c", "ext/twopence/target.h", "ext/twopence/target.c",
            "ext/twopence/util.h", "ext/twopence/util.c", "ext/library/twopence.h"
  s.extensions = "ext/twopence/extconf.rb"

  s.add_development_dependency "rake-compiler"
end
