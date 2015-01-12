
import twopence

target = twopence.Target("ssh:localhost");

target.inject("/etc/hosts", "/tmp/injected", mode = 0660)
target.extract("/etc/hosts", "hosts.copy", user = "okir")

target.run("/bin/pwd");

rc = target.run("/bin/blablabla")
print "Return code is", rc

out = bytearray();
target.run("/bin/ls", stdout = out)
print "Output has", len(out), "bytes"

cmd = twopence.Command("/bin/ls", user = "okir", stdout = bytearray());
target.run(cmd)
print "Output has", len(cmd.stdout()), "bytes"

print "Connect stdin to a file"
cmd = twopence.Command("/usr/bin/wc", stdin = "/etc/hosts");
target.run(cmd)

print "Test capturing with shared buffer"
cmd = twopence.Command("echo error>&2", stdout = bytearray());
target.run(cmd);
if len(cmd.stdout()) == 0:
  print "bad, expected stderr to be captured in stdout buffer"
else:
  print "stdout buffer has", len(cmd.stdout()), "bytes; good"

print "Test capturing with separate buffers"
cmd = twopence.Command("echo error>&2", stdout = bytearray(), stderr = bytearray());
target.run(cmd);
if len(cmd.stderr()) == 0:
  print "bad, expected stderr to be captured in stderr buffer"
else:
  print "stderr buffer has", len(cmd.stderr()), "bytes; good"
if len(cmd.stdout()) != 0:
  print "bad, expected stdout to be empty"
else:
  print "stdout buffer has", len(cmd.stdout()), "bytes; good"
