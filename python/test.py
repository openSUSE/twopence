
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

cmd = twopence.Command("/usr/bin/wc", stdin = "/etc/hosts");
target.run(cmd)
