#! /usr/bin/env ruby

require "twopence"
require "fileutils"

begin
#######################################################################
# Adapt the following line to your setup
#   $target = Twopence::init("virtio:/var/run/twopence/test.sock")
#   $target = Twopence::init("ssh:192.168.123.45")
#   $target = Twopence::init("serial:/dev/ttyS0")
$target = Twopence::init( YOUR_TARGET_HERE )
#######################################################################
rescue
  puts <<END
This Ruby script is meant as an example from which you could
copy and paste your own test scripts.

1 - copy this script to your home directory;
2 - modify it to declare $target variable;
3 - run it to see how it works;
4 - get your inspiration from the source code.

END
  exit 1
end

# This is the clean way to process interrupted twopence commands
trap("INT") { $target.interrupt_command(); exit() }

# We can send a command to the system under tests
printf("\nlocal, remote, command = $target.test_and_print_results('ls -l')\n")
local, remote, command = $target.test_and_print_results('ls -l')
printf("local=%d remote=%d command=%d\n\n", local, remote, command)

# We can avoid displaying the results
printf("\nlocal, remote, command = $target.test_and_drop_results('ping -c1 8.8.8.8')\n")
local, remote, command = $target.test_and_drop_results('ping -c1 8.8.8.8')
printf("local=%d remote=%d command=%d\n\n", local, remote, command)

# We don't need to process all these error codes
printf("\n$target.test_and_print_results('uname -a')\n")
$target.test_and_print_results('uname -a')
printf("\n\n")

# We can pipe a local command
# to another command on the remote system
printf("\nIO.popen('ls -l') ... $target.test_and_print_results('cat')\n")
save = $stdin.dup()
IO.popen("ls -l") do |ls_io|
  $stdin.reopen(ls_io)
  local, remote, command = $target.test_and_print_results('cat')
  printf("local=%d remote=%d command=%d\n\n", local, remote, command)
end
$stdin.reopen(save)

# We can work interactively with the remote system
printf("\nlocal, remote, command = $target.test_and_print_results('cat', 'root', 15)\n")
printf("(type Ctrl-D to exit, Ctrl-C to end)\n")
local, remote, command = $target.test_and_print_results('cat', 'root', 15)
printf("local=%d remote=%d command=%d\n\n", local, remote, command)

# We can redirect remote standard output and error to the same variable
printf("\noutput, local, remote, command = $target.test_and_store_results_together('ls -l . /oops')\n")
output, local, remote, command = $target.test_and_store_results_together('ls -l . /oops')
printf("output='%s'\n", output);
printf("local=%d remote=%d command=%d\n\n", local, remote, command)

# We can redirect remote standard output and error to separate variables
printf("\nstdout, stderr, local, remote, command = $target.test_and_store_results_separately('find /tmp -type f', 'nobody')\n")
stdout, stderr, local, remote, command = $target.test_and_store_results_separately('find /tmp -type f', 'nobody')
printf("stdout='%s'\n", stdout);
printf("stderr='%s'\n", stderr);
printf("local=%d remote=%d command=%d\n\n", local, remote, command)

# We can inject a local file into the remote system
printf("\nlocal, remote = $target.inject_file('/etc/services', 'test.txt')\n")
local, remote = $target.inject_file('/etc/services', 'test.txt')
printf("local=%d remote=%d\n\n", local, remote)

# We can extract a file from the remote system
# and store it locally
printf("\nlocal, remote = $target.extract_file('test.txt', 'etc_services')\n")
local, remote = $target.extract_file('test.txt', 'etc_services')
printf("local=%d remote=%d\n\n", local, remote)
FileUtils.rm("etc_services")
