#! /bin/bash
#
# Test script to exercise the Ruby wrapper.
#
# Provide a target on the command line using
#   ruby_test.sh virtio:/var/run/twopence/test.sock
#   ruby_test.sh ssh:192.168.123.45
#   ruby_test.sh serial:/dev/ttyS0
##########################################################

if [ $# -gt 0 ]; then
  export TARGET="$1"
fi

if [ -z "$TARGET" ]; then
  cat >&2 <<-EOF
  No twopence target given.
  Please specify a target as a command line argument, or
  using the TARGET environment variable.
EOF
fi

rspec=`type -p rspec`
if [ $? -ne 0 -o -z "$rspec" ]; then
  echo "rspec command not found; skipping ruby tests"
  exit 0
fi

# we can't pass command line arguments to rspec
# but we can use $TARGET environment variable
rspec spec/ruby_test.rb
