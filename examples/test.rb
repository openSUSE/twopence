#! /usr/bin/env ruby

require "twopence"

$user = ENV['USER']

#######################################################################
# Adapt the following line to your setup
#   $target = Twopence::init("virtio:/var/run/twopence/test.sock")
#   $target = Twopence::init("ssh:192.168.123.45")
#   $target = Twopence::init("serial:/dev/ttyS0")
$target = Twopence::init( YOUR_TARGET_HERE )
#######################################################################

printf("\ncommand='ls -l'\n")
rc, major, minor = $target.test_and_print_results($user, 'ls -l')
printf("host=%d server=%d command=%d\n\n", rc, major, minor)

printf("\ncommand='ping -c1 8.8.8.8', silent version\n")
rc, major, minor = $target.test_and_drop_results($user, 'ping -c1 8.8.8.8')
printf("host=%d server=%d command=%d\n\n", rc, major, minor)

printf("\nlocal 'ls -l' piped to command 'cat'\n")
save = $stdin.dup()
IO.popen("ls -l") do |ls_io|
  $stdin.reopen(ls_io)
  rc, major, minor = $target.test_and_print_results($user, 'cat')
  printf("host=%d server=%d command=%d\n\n", rc, major, minor)
end
$stdin.reopen(save)

printf("\ncommand 'cat' (type Ctrl-D to exit)\n")
rc, major, minor = $target.test_and_print_results($user, 'cat')
printf("host=%d server=%d command=%d\n\n", rc, major, minor)

printf("\ncommand 'ls -l /oops'\n")
out, err, rc, major, minor = $target.test_and_store_results_separately($user, 'ls -l /oops')
printf("stdout='%s'\n", out);
printf("stderr='%s'\n", err);
printf("host=%d server=%d command=%d\n\n", rc, major, minor)

printf("\ncommand 'find /etc -type s' run as user 'nobody'\n")
out, rc, major, minor = $target.test_and_store_results_together('nobody', 'find /etc -type s')
printf("output='%s'\n", out);
printf("host=%d server=%d command=%d\n\n", rc, major, minor)

printf("\ninject '/etc/services' => 'test.txt'\n")
rc, remote_rc = $target.inject_file($user, '/etc/services', 'test.txt', true)
printf("host=%d server=%d\n\n", rc, remote_rc)

printf("\ninject '/etc/services' => '/oops/test.txt'\n")
rc, remote_rc = $target.inject_file($user, '/etc/services', '/oops/test.txt', true)
printf("host=%d server=%d\n\n", rc, remote_rc)

printf("\nextract 'test.txt' => 'etc_services.txt'\n")
rc, remote_rc = $target.extract_file($user, 'test.txt', 'etc_services', true)
printf("host=%d server=%d\n\n", rc, remote_rc)

printf("\ncompare '/etc/services' with 'etc_services'\n")
if (system('diff -q /etc/services etc_services'))
  printf("files are identical\n")
end
system('rm etc_services')
printf("\n")

printf("\nextract 'oops' => 'bang'\n")
rc, remote_rc = $target.extract_file($user, 'oops', 'bang', true)
printf("host=%d server=%d\n\n", rc, remote_rc)
system('rm bang')

