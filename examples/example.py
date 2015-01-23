#!/usr/bin/env python

import twopence
import os

try:
  #######################################################################
  # Adapt the following line to your setup
  #   target = twopence::Target("virtio:/var/run/twopence/test.sock")
  #   target = twopence::Target("ssh:192.168.123.45")
  #   target = twopence::Target("serial:/dev/ttyS0")
  target = twopence.Target( YOUR_TARGET_HERE )
  #######################################################################
except NameError:
  print '''
This Python script is meant as an example from which you could
copy and paste your own test scripts.

1 - copy this script to your home directory;
2 - modify it to declare $TARGET variable;
3 - run it to see how it works;
4 - get your inspiration from the source code.

  '''
  exit(1)

# We can send a command to the system under tests
print "target.run('ls -l')"
status = target.run('ls -l')
print "status=", status.code
print

# We can avoid displaying the results
print "cmd = twopence.Command('ping -c1 8.8.8.8'); ..."
cmd = twopence.Command('ping -c1 8.8.8.8')
cmd.suppressOutput()
cmd.stderr = None
status = target.run(cmd)
print "status=", status.code
print

# We don't need to process the status code
print "target.run('uname -a')"
target.run('uname -a')
print

# We should be able to pipe a local command
# to another command on the remote system
# TODO: how to do exec("ls -l") | twopence_commad("cat") ?
print "TODO: pipe a local command to a remote command"
print

# We should be able to work interactively with the remote system
# TODO: does not work
print "TODO: be able to work interactively"
print
#try:
#  print "target.run('cat', timeout = 15)"
#  print "(type Ctrl-D to exit, Ctrl-C to end)\n"
#  status = target.run('cat', timeout = 15)
#  print "status=", status.code
#  print
#except SystemError:
#  print "timeout"
#  print

# We can redirect remote standard output and error to the same variable
print "cmd = twopence.Command('ls -l . /ooops'); ..."
cmd = twopence.Command('ls -l . /oops')
cmd.suppressOutput()
status = target.run(cmd)
print "output='", status.stdout, "'"
print "status=", status.code

# We can redirect remote standard output and error to separate variables
print "cmd = twopence.Command('find /tmp -type f'); ..."
cmd = twopence.Command('find /tmp -type f')
cmd.suppressOutput()
cmd.user = 'nobody'
cmd.stdout = bytearray()
cmd.stderr = bytearray()
status = target.run(cmd)
print "stdout='", status.stdout, "'"
print "stderr='", status.stderr, "'"

# We can inject a local file into the remote system
print "target.inject('/etc/services', 'test.txt')"
target.inject('/etc/services', 'test.txt')
print

# We can extract a file from the remote system
# and store it locally
print "target.extract('test.txt', 'etc_services')"
target.extract('test.txt', 'etc_services')
print
os.remove("etc_services")
