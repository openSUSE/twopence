
import twopence

target = twopence.Target("ssh:localhost");

target.inject("/etc/hosts", "/tmp/injected", mode = 0660)
target.extract("/etc/hosts", "hosts.copy", user = "okir")

target.run("/bin/pwd");

status = target.run("/bin/blablabla")
print "Return code is", status.code

out = bytearray();
target.run("/bin/ls", stdout = out)
print "Output has", len(out), "bytes"

cmd = twopence.Command("/bin/ls", user = "okir");
cmd.suppressOutput()
cmd.stderr = None
target.run(cmd)
print "command stdout=", type(cmd.stdout), "; stderr=", type(cmd.stderr);
print "Output has", len(cmd.stdout), "bytes"

print "Connect stdin to a file"
cmd = twopence.Command("/usr/bin/wc", stdin = "/etc/hosts");
target.run(cmd)

print "Test capturing with shared buffer"
cmd = twopence.Command("echo error>&2");
status = target.run(cmd);
if len(status.stdout) == 0:
  print "bad, expected stderr to be captured in stdout buffer"
else:
  print "stdout buffer has", len(status.stdout), "bytes; good"

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
