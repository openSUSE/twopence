#!/usr/bin/env python

import twopence

#######################################################################
# Adapt the following line to your setup
#   target = twopence::Target("virtio:/var/run/twopence/test.sock");
#   target = twopence::Target("ssh:192.168.123.45");
#   target = twopence::Target("serial:/dev/ttyS0");
target = twopence.Target( YOUR_TARGET_HERE );
#######################################################################

print "command='/bin/pwd'"
target.run("/bin/pwd");
print

print "inject '/etc/hosts' => '/tmp/injected' with mode 0660"
# TODO: move functionality from binding to library
print "(note: defining the file mode should not be done in the"
print "       Python binding, but in the underlying library)"
target.inject("/etc/hosts", "/tmp/injected", mode = 0660)
print

print "extract '/etc/hosts' => 'hosts.copy' as user 'nobody'"
target.extract("/etc/hosts", "hosts.copy", user = "nobody")
print

print "command='/bin/blablabla'"
status = target.run("/bin/blablabla")
print "Return code is", status.code
if not(status):
  print "Command failed as expected, message:", status.message
print

print "command='kill -9 $$'"
status = target.run("kill -9 $$")
print "Return code is", status.code
if not(status):
  print "Command failed as expected, message:", status.message
print

print "command='/bin/ls' to byte array"
out = bytearray();
target.run("/bin/ls", stdout = out)
print "Output has", len(out), "bytes"
print

print "verify commandline attribute"
cmd = twopence.Command("/bin/ls");
if cmd.commandline != "/bin/ls":
	print "Bad commandline:", cmd.commandline
else:
	print "Good, commandline attribute returns /bin/ls"
print

print "verify user attribute"
cmd = twopence.Command("/bin/ls", user = "joedoe");
if cmd.user != "joedoe":
	print "Bad user attribute:", cmd.user, "(expected joedoe)"
else:
	print "Good, user attribute returns joedoe"
print

print "command='/bin/ls' with suppressed output"
cmd = twopence.Command("/bin/ls", user = "nobody");
cmd.suppressOutput()
cmd.stderr = None
target.run(cmd)
print "command stdout=", type(cmd.stdout), "; stderr=", type(cmd.stderr);
print "Output has", len(cmd.stdout), "bytes"
print

print "command='echo' to stderr with shared buffer"
cmd = twopence.Command("echo error>&2");
status = target.run(cmd);
if len(status.stdout) == 0:
  print "bad, expected stderr to be captured in stdout buffer"
else:
  print "stdout buffer has", len(status.stdout), "bytes; good"
print

print "command='echo' to stderr with separate buffers"
print "Test capturing with separate buffers"
cmd = twopence.Command("echo error>&2", stdout = bytearray(), stderr = bytearray());
status = target.run(cmd);
if len(status.stderr) == 0:
  print "bad, expected stderr to be captured in stderr buffer"
else:
  print "stderr buffer has", len(status.stderr), "bytes; good"
if len(status.stdout) != 0:
  print "bad, expected stdout to be empty"
else:
  print "stdout buffer has", len(status.stdout), "bytes; good"
print

print "command='/usr/bin/wc' with stdin connected to a file"
cmd = twopence.Command("/usr/bin/wc", stdin = "/etc/hosts");
target.run(cmd)
print

print "command='cat' with stdin connected to the result of 'ls'"
# TODO: local command piped to remote command
print "(note: test to be written)"
print

print "command='cat' (press Ctrl-D to end or Ctrl-C to interrupt)"
# TODO: not functional yet
print "(note: not functional yet)"
cmd = twopence.Command("cat");
target.run(cmd)
print

