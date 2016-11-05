#!/usr/bin/env python
#
# Test script to exercise the Python wrapper.
#
# Provide a target on the command line using
#   python_test.py virtio:/var/run/twopence/test.sock
#   python_test.py ssh:192.168.123.45
#   python_test.py serial:/dev/ttyS0
##########################################################

testuser = "testuser"

import twopence
import sys
import os
import traceback

twopence.setDebugLevel(0)

targetSpec = None
if len(sys.argv) > 1:
	targetSpec = sys.argv[1]
if not targetSpec:
	print "Expected twopence target as argument"
	sys.exit(1)

target = twopence.Target(targetSpec);

allErrorsFatal = False
testCaseRunning = False
testCaseStatus = None
numFailed = 0
numErrors = 0
numSkipped = 0
numTests = 0

def testCaseError(msg):
	global numFailed, numErrors, testCaseRunning

	numFailed = numFailed + 1
	numErrors = numErrors + 1
	print "### ERROR: " + msg
	testCaseStatus = "ERROR"

def testCaseBegin(msg):
	global testCaseRunning, testCaseStatus, numTests

	if testCaseRunning:
		testCaseError("Trying to start a new test case while another is still running");

	print
	print "### TEST: " + msg
	testCaseRunning = True;
	testCaseStatus = None;
	numTests += 1

def testCaseFail(msg):
	global testCaseStatus

	print "### " + msg
	if not testCaseStatus:
		testCaseStatus = "FAILED"

def testCaseSkip(msg):
	global testCaseStatus

	print "### " + msg
	if not testCaseStatus:
		testCaseStatus = "SKIPPED"

def testCaseCheckStatus(status, expectExitCode = 0):
	print # command may not have printed a newline
	print "Transaction finished; status %d" % status.code
	if status.code != expectExitCode:
		testCaseFail("command exited with status %d, expected %d" % (status.code, expectExitCode));
		return False
	return True

def testCaseCheckStatusQuiet(status, expectExitCode = 0):
	if status.code != expectExitCode:
		print # command may not have printed a newline
		testCaseFail("command exited with status %d, expected %d" % (status.code, expectExitCode));
		return False
	return True

def testCaseSetupTimerTest():
	global __testCaseTimeOut
	__testCaseTimeOut = False

def testCaseTimerCallback():
	global __testCaseTimeOut
	__testCaseTimeOut = True

def testCaseTimedOut():
	global __testCaseTimeOut
	return __testCaseTimeOut

def testCaseVerifyPythonAttr(object, attrname, expect):
	typeName = type(object).__name__

	value = getattr(object, attrname)
	if value != expect:
		testCaseFail("%s object: attribute %s has unexpected value %s (should be %s)" %
			(typeName, attrname, value, expect))
		return False

	print "Attribute verify OK: %s.%s=%s" % (typeName, attrname, value)
	return True

def testCaseVerifyPythonSetAttr(object, attrname, value):
	typeName = type(object).__name__

	print "Setting attribute %s.%s=%s"  % (typeName, attrname, value)
	setattr(object, attrname, value)

	testCaseVerifyPythonAttr(object, attrname, value)

def testCaseException():
	info = sys.exc_info()
	testCaseFail("caught python exception %s: %s" % info[0:2])
	traceback.print_tb(info[2])

def testCaseReport():
	global testCaseStatus, testCaseRunning, numFailed, numSkipped
	global allErrorsFatal

	if testCaseStatus:
		print "### " + testCaseStatus
		if testCaseStatus == "SKIPPED":
			numSkipped = numSkipped + 1
		else:
			numFailed = numFailed + 1
	else:
		print "### SUCCESS"
	print

	testCaseRunning = False

	if allErrorsFatal and testCaseStatus == "FAILED":
		testSuiteExit()

def testSuiteExit():
	global testCaseRunning, numTests, numFailed, numErrors

	if testCaseRunning:
		testCaseError("Finishing test suite while a test case is still running");

	if numFailed != 0 or numErrors != 0:
		exitStatus = 1
		result = "FAILED"
	else:
		exitStatus = 0
		result = "SUCCESS"

	print "### SUMMARY %d %d %d %d" % (numTests, numSkipped, numFailed, numErrors)
	print
	print "Overall test suite status:", result
	print " %4d tests run" % numTests
	print " %4d failed" % numFailed
	print " %4d errors" % numErrors
	print " %4d skipped" % numSkipped

	sys.exit(exitStatus)

##################################################################
# Individual test cases start here
##################################################################

testCaseBegin("Check the plugin type")
try:
	t = target.type
	print "plugin type is", t
	if t not in ("ssh", "virtio", "serial", "tcp", "chroot", "local"):
		testCaseFail("Unknwon plugin type \"%s\"" % t)
except:
	testCaseException()
testCaseReport()

testCaseBegin("Run command /bin/pwd")
try:
	status = target.run("/bin/pwd")
	if testCaseCheckStatus(status):
		pwd = str(status.stdout).strip();
		if pwd != "/" and pwd != '/root':
			testCaseFail("expected pwd to print '/' or '/root', instead got '%s'" % pwd);
except:
	testCaseException()
testCaseReport()

testCaseBegin("inject '/etc/hosts' => '/tmp/injected' with mode 0660")
try:
	target.inject("/etc/hosts", "/tmp/injected", mode = 0660)
except:
	testCaseException()
testCaseReport()

testCaseBegin("extract injected file again")
try:
	target.extract("/tmp/injected", "etc_hosts")
	rc = os.system("cmp /etc/hosts etc_hosts")
	if rc == 0:
		print "Good, /etc/hosts and downloaded file match"
	else:
		testCaseFail("Original /etc/hosts and downloaded file differ");
		rc = os.system("diff -u /etc/hosts etc_hosts")
except:
	testCaseException()
os.remove("etc_hosts")
testCaseReport()

testCaseBegin("extract '/etc/hosts' => 'etc_hosts' as user '%s'" % testuser)
try:
	target.extract("/etc/hosts", "etc_hosts", user = testuser)
except:
	testCaseException()
os.remove("etc_hosts")
testCaseReport()

testCaseBegin("try to extract non-existant file")
try:
	rc = target.extract("/does/not/exist", "crap.txt")
	testCaseFail("extract returned %s (should have thrown an exception)" % rc);
except:
	pass
	print "Good, command threw an exception as expected"
testCaseReport()

testCaseBegin("try to upload to non-existant file")
try:
	rc = target.inject("/dev/null", "/does/not/exist")
	testCaseFail("inject returned %s (should have thrown an exception)" % rc);
except:
	print "Good, command threw an exception as expected"
testCaseReport()

testCaseBegin("Verify twopence.Command attributes")
try:
	outbuf = bytearray();
	errbuf = bytearray();
	cmd = twopence.Command("/bin/something", user = "eric",
				 timeout = 123,
				 stdin = "/local/file", 
				 stdout = outbuf,
				 stderr = errbuf,
				 suppressOutput = True);
	print "Verify commandline attribute"
	if cmd.commandline != "/bin/something":
		testCaseFail("cmd.commandline attribute invalid")
	print "Verify user attribute"
	if cmd.user != "eric":
		testCaseFail("cmd.user attribute invalid")
	print "Verify timeout attribute"
	if cmd.timeout != 123:
		testCaseFail("cmd.timeout attribute invalid")
	print "Verify stdout attribute"
	if cmd.stdout != outbuf:
		testCaseFail("cmd.stdout attribute invalid")
	print "Verify stderr attribute"
	if cmd.stderr != errbuf:
		testCaseFail("cmd.stderr attribute invalid")

	print "Change user attribute"
	cmd.user = "root"
	if cmd.user != "root":
		testCaseFail("unable to set cmd.user attribute")
	print "Change timeout attribute"
	cmd.timeout = 12;
	if cmd.timeout != 12:
		testCaseFail("unable to set cmd.timeout attribute")
	print "Change stdout attribute"
	cmd.stdout = errbuf;
	if cmd.stdout != errbuf:
		testCaseFail("unable to set cmd.stdout attribute")
	print "Change stderr attribute"
	cmd.stderr = outbuf;
	if cmd.stderr != outbuf:
		testCaseFail("unable to set cmd.stderr attribute")

	# Not yet supported:
	# useTty
	# suppressOutput
except:
	testCaseException()
testCaseReport()

testCaseBegin("run command /bin/blablabla (should fail)")
try:
	status = target.run("/bin/blablabla")
	testCaseCheckStatus(status, 127)
except:
	testCaseException()
testCaseReport()

testCaseBegin("run command kill -9 $$")
try:
	status = target.run("bash -c 'kill -9 $$'")
	testCaseCheckStatus(status, 256 + 9)
except:
	testCaseException()
testCaseReport()

testCaseBegin("verify that command is run as root by default")
try:
	status = target.run("id -un")
	if testCaseCheckStatus(status):
		user = str(status.stdout).strip()
		if user == "root":
			print "Good, command was run as root"
		else:
			testCaseFail("Command was run as %s instead of user root" % user)
except:
	testCaseException()
testCaseReport()


testCaseBegin("verify that command is run as %s" % testuser)
try:
	status = target.run("id -un", user = testuser)
	if testCaseCheckStatus(status):
		user = str(status.stdout).strip()
		if user == testuser:
			print "Good, command was run as %s" % testuser
		else:
			testCaseFail("Command was run as %s instead of user %s" % (user, testuser))
except:
	testCaseException()
testCaseReport()


testCaseBegin("command='/bin/ls' to byte array")
try:
	out = bytearray();
	status = target.run("/bin/ls", stdout = out)
	testCaseCheckStatus(status)
	if len(out) == 0:
		testCaseFail("No output to buffer");
	else:
		print "Good, output has", len(out), "bytes"
except:
	testCaseException()
testCaseReport()

testCaseBegin("verify commandline attribute")
try:
	cmd = twopence.Command("/bin/ls");
	if cmd.commandline != "/bin/ls":
		testCaseFail("Bad commandline: " . cmd.commandline)
	else:
		print "Good, commandline attribute returns /bin/ls"
except:
	testCaseException()
testCaseReport()

testCaseBegin("verify user attribute")
try:
	cmd = twopence.Command("/bin/ls", user = "joedoe");
	if cmd.user != "joedoe":
		testCaseFail("Bad user attribute: %s (expected joedoe)" % cmd.user)
	else:
		print "Good, user attribute returns joedoe"
except:
	testCaseException()
testCaseReport()

testCaseBegin("command='/bin/ls' with suppressed output")
try:
	cmd = twopence.Command("/bin/ls");
	cmd.suppressOutput()
	cmd.stderr = None
	status = target.run(cmd)
	if testCaseCheckStatus(status):
		print "command stdout=", type(cmd.stdout), "; stderr=", type(cmd.stderr);
		if len(cmd.stdout) == 0:
			testCaseFail("ls command didn't generate any output")
		else:
			print "Good, output has", len(cmd.stdout), "bytes"
except:
	testCaseException()
testCaseReport()


testCaseBegin("run command as %s" % testuser)
try:
	cmd = twopence.Command("id -un", user = testuser);
	cmd.suppressOutput()
	cmd.stderr = None
	status = target.run(cmd)
	if testCaseCheckStatus(status):
		user = str(cmd.stdout).strip()
		if user != testuser:
			testCaseFail("command ran as user %s instead of %s" % (user, testuser))
		else:
			print "Good, command ran as user %s" % testuser
except:
	testCaseException()
testCaseReport()



testCaseBegin("command='echo' to stderr with shared buffer")
try:
	cmd = twopence.Command("bash -c 'echo error>&2'");
	status = target.run(cmd);
	if testCaseCheckStatus(status):
		if len(status.stdout) == 0:
			testCaseFail("bad, expected stderr to be captured in stdout buffer")
		else:
			print "Good, stdout buffer has", len(status.stdout), "bytes"
except:
	testCaseException()
testCaseReport()


testCaseBegin("command='echo' to stderr with separate buffers")
try:
	cmd = twopence.Command("bash -c 'echo error>&2'", stdout = bytearray(), stderr = bytearray());
	status = target.run(cmd);
	if testCaseCheckStatus(status):
		if len(status.stderr) == 0:
			testCaseFail("bad, expected stderr to be captured in stderr buffer")
		else:
			print "stderr buffer has", len(status.stderr), "bytes; good"
		if len(status.stdout) != 0:
			testCaseFail("bad, expected stdout to be empty")
		else:
			print "stdout buffer has", len(status.stdout), "bytes; good"
except:
	testCaseException()
testCaseReport()



testCaseBegin("command='/usr/bin/wc' with stdin connected to a file")
try:
	cmd = twopence.Command("wc", stdin = "/etc/hosts");
	status = target.run(cmd)
	if testCaseCheckStatus(status):
		remoteOut = str(status.stdout).split()
		localOut = str(os.popen("wc </etc/hosts").read()).split()
		if localOut != remoteOut:
			testCaseFail("output differs")
			print "local:  ", localOut
			print "remote: ", remoteOut
except:
	testCaseException()
testCaseReport()


testCaseBegin("command='/usr/bin/wc' with stdin connected to a buffer")
try:
	cmd = twopence.Command("wc", stdin = bytearray("aa\nbb\ncc\n"))
	status = target.run(cmd)
	if testCaseCheckStatus(status):
		word = str(status.stdout).split()[0]
		if int(word) != 3:
			testCaseFail("command returned wrong number of lines (got %s, expected 3)" % word)
except:
	testCaseException()
testCaseReport()

testCaseBegin("command='/usr/bin/wc' with stdin connected to the output of a local command")
try:
	import subprocess

	print "Running local command 'cat /etc/services'"
	p = subprocess.Popen("cat /etc/services", shell=True, stdout=subprocess.PIPE)
	if not p:
		testCaseFail("unable to open subprocess")
	else:
		print "Running remote command 'wc' with stdin connected to local stdout"
		cmd = twopence.Command("wc", stdin = p.stdout);
		status = target.run(cmd)
		if testCaseCheckStatus(status):
			remoteOut = str(status.stdout).split()
			localOut = str(os.popen("wc </etc/services").read()).split()
			if localOut != remoteOut:
				testCaseFail("output differs")
				print "local:  ", localOut
				print "remote: ", remoteOut
			else:
				print "Remote output matches output of running wc locally"
except:
	testCaseException()
testCaseReport()

testCaseBegin("run a command producing lots of output")
try:
	cmd = twopence.Command("dd if=/dev/zero bs=1k count=1k", suppressOutput = 1)
	status = target.run(cmd)
	if testCaseCheckStatus(status):
		got_bytes = len(status.stdout)
		# We do not check the total amount of data received;
		# right now, the buffer size is capped at 64K which is not
		# useful in this context
except:
	testCaseException()
testCaseReport()

testCaseBegin("Run command in tty")
try:
	cmd = twopence.Command("tty")
	cmd.useTty = True
	cmd.timeout = 5
	status = target.run(cmd)
	if testCaseCheckStatus(status):
		dev = str(status.stdout).strip();
		if dev[:4] != "/dev":
			testCaseFail("expected command to return a device path, instead got '%s'" % dev);
except:
	testCaseException()
testCaseReport()


try:
	testCaseBegin("check whether target supports backgrounded commands")
	target.wait()
	print "It looks like it does"
	backgroundingSupported = True
except:
	print "No, it does not"
	backgroundingSupported = False
testCaseReport()

testCaseBegin("run /bin/pwd in the background")
if not(backgroundingSupported):
    testCaseSkip("background execution not available for %s plugin right now" % target.type)
else:
    try:
	cmd = twopence.Command("/bin/pwd", background = 1);
	if target.run(cmd) != True:
		testCaseFail("Target.run() of a backgrounded command should return True")
	elif not cmd.pid:
		testCaseFail("Target.run() of a backgrounded command should set the command's pid")
	else:
		status = target.wait()
		if status == None:
			testCaseFail("Did not find any process to wait for")
		elif status.command != cmd:
			testCaseFail("target.wait() returned a different process (pid=%d)" % status.command.pid)
		elif testCaseCheckStatus(status):
			pwd = str(status.stdout).strip();
			if pwd != "/" and pwd != '/root':
				testCaseFail("expected pwd to print '/' or '/root', instead got '%s'" % pwd);
	if cmd.pid:
		testCaseFail("command pid should be reset to 0 after completion")
    except:
	testCaseException()
target.waitAll()
testCaseReport()

testCaseBegin("run several processes in the background")
if not(backgroundingSupported):
    testCaseSkip("background execution not available for %s plugin right now" % target.type)
else:
    try:
	times = range(6, 0, -1)
	cmds = []
	for time in times:
		cmd = twopence.Command("sleep %d" % time, background = 1);
		print "Starting ", cmd.commandline
		target.run(cmd)

	nreaped = 0
	while True:
		status = target.wait()
		if status == None:
			break
		print "finished command:", status.command.commandline
		if not(status):
			testCaseFail("command failed")
		nreaped = nreaped + 1;

	ntimes = len(times)
	if nreaped != ntimes:
		testCaseFail("Reaped %d commands, expected %d" % (nreaped, ntimes))
    except:
	testCaseException()
testCaseReport()

testCaseBegin("wait for a specific process")
if not(backgroundingSupported):
    testCaseSkip("background execution not available for %s plugin right now" % target.type)
else:
    try:
	cmd1 = twopence.Command("sleep 2", background = 1);
	target.run(cmd1);
	print "cmd1: %s (pid %d)" % (cmd1.commandline, cmd1.pid)

	cmd2 = twopence.Command("sleep 4", background = 1);
	target.run(cmd2);
	print "cmd2: %s (pid %d)" % (cmd2.commandline, cmd2.pid)

	# Now wait for the second command, which actually takes
	# longer.
	status = target.wait(cmd2);
	if not(status):
		testCaseFail("command failed")
	elif status.command == cmd2:
		print "finished command:", status.command.commandline
	else:
		testCaseFail("target.wait() returned the wrong command")

	status = target.wait();
	if not(status):
		testCaseFail("command failed")
	else:
		print "finished command:", status.command.commandline
    except:
	testCaseException()
testCaseReport()

testCaseBegin("combine foreground and background process")
if not(backgroundingSupported):
    testCaseSkip("background execution not available for %s plugin right now" % target.type)
else:
    try:
	cmd1 = twopence.Command("sleep 2", background = 1);
	target.run(cmd1);
	print "cmd1: %s (pid %d)" % (cmd1.commandline, cmd1.pid)

	cmd2 = twopence.Command("sleep 4", background = 0);
	print "cmd2: %s (foreground)" % cmd2.commandline

	status = target.run(cmd2);
	if not(status):
		testCaseFail("command failed")
	elif status.command == cmd1:
		testCaseFail("target.wait() returned the wrong command")
	else:
		print "finished foreground command"

	status = target.wait();
	if not(status):
		testCaseFail("command failed")
	else:
		print "finished command:", status.command.commandline
    except:
	testCaseException()
testCaseReport()

testCaseBegin("verify that target.waitAll() waits for all commands")
if not(backgroundingSupported):
    testCaseSkip("background execution not available for %s plugin right now" % target.type)
else:
    try:
	for time in range(1, 5):
		target.run("sleep 2", background = 1);

	status = target.waitAll(print_dots = 1);
	if status == None:
		testCaseFail("waitAll returns None")
	elif status.code != 0:
		testCaseFail("one or more commands failed")
	else:
		print "Good, waitAll returns an exit status of 0"
	if target.wait() != None:
		testCaseFail("there were still commands left after waitAll returned")
    except:
	testCaseException()
testCaseReport()

testCaseBegin("verify that target.waitAll() propagates errors")
if not(backgroundingSupported):
    testCaseSkip("background execution not available for %s plugin right now" % target.type)
else:
    try:
	target.run("sleep 1", background = 1);
	target.run("sleep 2; exit 2", background = 1)
	target.run("sleep 3", background = 1);

	status = target.waitAll(print_dots = 1);
	if status == None:
		testCaseFail("waitAll didn't return any status")
	elif status.code != 2:
		testCaseFail("waitAll should have reported an error")
	else:
		print "Good, waitAll returns an exit status of 2"
	if target.wait() != None:
		testCaseFail("there were still commands left after waitAll returned")
    except:
	testCaseException()
testCaseReport()

crossTargetConcurrencySupport = backgroundingSupported
if target.type != "virtio" and target.type != "tcp" and target.type != "serial":
    crossTargetConcurrencySupport = False

testCaseBegin("run concurrent processes on multiple targets")
if not(crossTargetConcurrencySupport):
    testCaseSkip("cross-target concurrency not available for %s plugin right now" % target.type)
else:
    try:
	# Just open a second connection to the same server
	target2 = twopence.Target(targetSpec);

	cmd1 = twopence.Command("sh -c 'for x in `seq 1 20`; do echo -n A; sleep 0.2; done'", background = 1);
	target.run(cmd1);
	print "cmd1: %s (pid %d)" % (cmd1.commandline, cmd1.pid)

	cmd2 = twopence.Command("sh -c 'for x in `seq 1 20`; do echo -n B; sleep 0.2; done'", background = 1);
	target.run(cmd2);
	print "cmd2: %s (pid %d)" % (cmd2.commandline, cmd2.pid)

	status = target.wait();
	print "\n"

	if not(status):
		testCaseFail("command failed")
	else:
		print "finished command:", status.command.commandline

	status = target.wait();
	if not(status):
		testCaseFail("command failed")
	else:
		print "finished command:", status.command.commandline

	target2 = None
    except:
	testCaseException()
testCaseReport()

testCaseBegin("Verify twopence.Transfer attributes")
try:
	xfer = twopence.Transfer("/remote/filename", localfile = "/local/filename", permissions = 0421);
	if xfer.remotefile != "/remote/filename":
		testCaseFail("xfer.remotefile attribute invalid")
	if xfer.localfile != "/local/filename":
		testCaseFail("xfer.localfile attribute invalid")
	if xfer.permissions != 0421:
		testCaseFail("xfer.permissions attribute invalid")
except:
	testCaseException()
testCaseReport()

testCaseBegin("sendfile '/etc/hosts' => '/tmp/injected'")
try:
	xfer = twopence.Transfer("/tmp/injected", localfile = "/etc/hosts");
	status = target.sendfile(xfer);
	testCaseCheckStatus(status)
except:
	testCaseException()
testCaseReport()

testCaseBegin("downloading file again using recvfile")
try:
	xfer = twopence.Transfer("/tmp/injected", localfile = "etc_hosts");
	status = target.recvfile(xfer);
	if testCaseCheckStatus(status):
		rc = os.system("cmp /etc/hosts etc_hosts")
		if rc == 0:
			print "Good, /etc/hosts and downloaded file match"
		else:
			testCaseFail("Original /etc/hosts and downloaded file differ");
			rc = os.system("diff -u /etc/hosts etc_hosts")
except:
	testCaseException()
target.run("rm -f /tmp/injected");
os.remove("etc_hosts")
testCaseReport()


##################################################################
# This file mode stuff is not really accurate, at least
# with ssh. The sshd daemon's umask will modify the file bits anyway;
# plus the permissions of an existing file to not get updated anyway.
# We would have to chmod the file explicitly in the client code for
# this to work as expected.
##################################################################
# testCaseBegin("verify that sendfile assigns the requested permissions")
# try:
# 	xfer = twopence.Transfer("/tmp/injected", localfile = "_etc_hosts");
# 	cmd = twopence.Command("stat -c 0%a /tmp/injected")
# 	cmd.suppressOutput();
# 
# 	for xfer.permissions in (0400, 0111, 0666, 0421):
# 		print "creating file with mode 0%o" % xfer.permissions
# 		status = target.sendfile(xfer);
# 		if not testCaseCheckStatusQuiet(status):
# 			break
# 
# 		cmd.stdout = bytearray();
# 		status = target.run(cmd)
# 		if not testCaseCheckStatusQuiet(status):
# 			break
# 
# 		expect = "0%03o" % xfer.permissions
# 		mode = str(status.stdout).strip()
# 		if mode == expect:
# 			print "Good, file mode is set to %s" % mode
# 		else:
# 			testCaseFail("File mode should be %s, but is %s" % (expect, mode));
# 			break
# 
# 		target.run("rm -f /tmp/injected");
# except:
# 	testCaseException()
# target.run("rm -f /tmp/injected");
# testCaseReport()

buffer = bytearray()
testCaseBegin("receive file to a buffer");
try:
	print "Downloading /etc/hosts to a python buffer"
	xfer = twopence.Transfer("/etc/hosts");
	status = target.recvfile(xfer);
	if testCaseCheckStatus(status):
		if len(status.buffer) == 0:
			testCaseFail("Downloaded buffer is empty");
		else:
			print "Good, we received some data"
			buffer = status.buffer;
except:
	testCaseException()
testCaseReport()

testCaseBegin("send a file from a buffer");
try:
	print "Uploading buffer to /tmp/injected"
	xfer = twopence.Transfer("/tmp/injected", data = buffer);
	status = target.sendfile(xfer);
	if testCaseCheckStatus(status):
		print "/tmp/injected should now contain the same data as /etc/hosts"
		if not target.run("cmp /etc/hosts /tmp/injected"):
			testCaseFail("Uploaded data does not match original file");
		else:
			print "Great, our uploaded data agrees with the original file";
except:
	testCaseException()
target.run("rm -f /tmp/injected");
testCaseReport()

testCaseBegin("verify that we can pass an environment variable")
try:
	value = "12345"

	print "Setting FOOBAR=%s and running echo $FOOBAR" % value
	cmd = twopence.Command("echo $FOOBAR", quiet = True)
	cmd.setenv("FOOBAR", value)
	status = target.run(cmd)
	if testCaseCheckStatus(status):
		output = str(status.stdout).strip()
		if output != value:
			testCaseFail("Command should have printed \"%s\", but gave us \"%s\"" % (value, output))
		else:
			print "Great, SUT echoed back \"%s\"" % value
except:
	testCaseException()
testCaseReport()

testCaseBegin("verify that we can inspect the environment locally")
try:
	print "Setting several environment variables and inspecting the command's environ attribute"
	setenv = [["foo", "1234"], ["bar", "5678"]]
	cmd = twopence.Command("irrelevant")
	for pair in setenv:
		cmd.setenv(pair[0], pair[1])

	# We cannot just test "if setenv == cmd.environ" because that compares
	# references, not values
	match = True
	value = cmd.environ

	if len(value) != len(setenv):
		match = True
	for i in range(0, len(setenv)):
		set = setenv[i]
		get = value[i]
		if set[0] != get[0] or set[1] != get[1]:
			match = False

	if not match:
		testCaseFail("cmd.environ does not match what we assigned")
		print "Here's what we set:"
		for pair in setenv:
			print "%s=%s" % (pair[0], pair[1])
		print "And here's what we get:"
		for pair in cmd.environ:
			print "%s=%s" % (pair[0], pair[1])
	else:
		print "Great, cmd.environ returns the expected data"
except:
	testCaseException()
testCaseReport()

testCaseBegin("verify that cmd.unsetenv works")
try:
	print "Setting and unsetting variable foobar"
	cmd = twopence.Command("irrelevant")
	cmd.setenv("foobar", "1234")
	cmd.unsetenv("foobar")
	if len(cmd.environ) != 0:
		testCaseFail("cmd.environ should be empty")
except:
        testCaseException()
testCaseReport()

testCaseBegin("verify that we can pass environment variables per target")
try:
	value = "abcdef"

	print "Setting FOOBAR=%s in the target environment and running echo $FOOBAR" % value
	target.setenv("FOOBAR", value)
	cmd = twopence.Command("echo $FOOBAR", quiet = True)
	status = target.run(cmd)
	if testCaseCheckStatus(status):
		output = str(status.stdout).strip()
		if output == value:
			print "Great, SUT echoed back \"%s\"" % value
		else:
			testCaseFail("Command should have printed \"%s\", but gave us \"%s\"" % (value, output))
except:
	testCaseException()
testCaseReport()

testCaseBegin("verify that Command environment takes precedence over target environment")
try:
	value = "ghijklm"

	print "Setting FOOBAR=%s in the command environment and running echo $FOOBAR" % value
	cmd = twopence.Command("echo $FOOBAR", quiet = True)
	cmd.setenv("FOOBAR", value)
	status = target.run(cmd)
	if testCaseCheckStatus(status):
		output = str(status.stdout).strip()
		if output == value:
			print "Great, SUT echoed back \"%s\"" % value
		else:
			testCaseFail("Command should have printed \"%s\", but gave us \"%s\"" % (value, output))
except:
        testCaseException()
testCaseReport()

testCaseBegin("verify that we can unset per-target environment variables")
try:
	print "Setting several environment variables and inspecting the command's environ attribute"
	target.unsetenv("FOOBAR")

	cmd = twopence.Command("echo $FOOBAR", quiet = True)
	status = target.run(cmd)
	if testCaseCheckStatus(status):
		output = str(status.stdout).strip()
		if len(output) == 0:
			print "Great, the variable was unset"
		else:
			testCaseFail("Command gave us \"%s\" (should have been empty)" % (output))
except:
	testCaseException()
testCaseReport()

testCaseBegin("Check chat scripting")
try:
	mydata = "here it is"

	chat = target.chat("read -p 'Give it to me: ' DATA; echo -n \"data=$DATA\"")
	print "Waiting for prompt"
	if not chat.expect("to me:", timeout = 5):
		testCaseFail("did not receive prompt")
	else:
		print "Received prompt, sending answer"
		chat.send("%s\n" % mydata);

		print "Waiting for command to print data="
		if not chat.expect("data="):
			testCaseFail("did not receive answer")
		else:
			print "Got it; receiving rest of the line"
			answer = chat.recvline()
			if not answer:
				testCaseFail("did not receive answer")
			elif answer.strip() != mydata:
				testCaseFail("did not receive expected answer, remote echoed \"%s\"" % answer);
			else:
				print "Great, received expected data"

		if not chat.wait():
			testCaseFail("chat command exited with non-zero status")
except:
	testCaseException()
testCaseReport()

testCaseBegin("Check chat scripting with multiple expect strings")
try:
	mydata = "here it is"

	chat = target.chat("echo This is a BadSurprise - not a Success")
	print "Waiting for prompt"
	if not chat.expect(["Success", "Bad", "BadSurprise"], timeout = 5):
		testCaseFail("timed out waiting for output")
	elif chat.found == "BadSurprise":
		print "Good, found the expected string \"BadSurprise\""
	else:
		print "chat.expect() found string \"%s\"" % chat.found
		testCaseFail("chat.expect() returned wrong result (should have been BadSurprise)")
except:
	testCaseException()
testCaseReport()

testCaseBegin("Check timer attributes")
try:
	testCaseSetupTimerTest()

	timer = twopence.Timer(60)
	print "Timer id is", timer.id

	testCaseVerifyPythonSetAttr(timer, "callback",  testCaseTimerCallback)
	testCaseVerifyPythonAttr(timer, "state",  "active")

	print "Cancelling timer"
	timer.cancel()
	testCaseVerifyPythonAttr(timer, "state",  "cancelled")

	del timer
except:
	testCaseException()
testCaseReport()

testCaseBegin("Check timer")
try:
	testCaseSetupTimerTest()

	print "Set a 2 second timer, and run a command that sleeps for 4 seconds"
	timer = twopence.Timer(2, callback = testCaseTimerCallback)
	status = target.run("sleep 4")

	testCaseVerifyPythonAttr(timer, "state", "expired")
	testCaseVerifyPythonAttr(timer, "remaining", 0)
	if testCaseTimedOut():
		print "OK, callback was invoked"
	else:
		testCaseFail("callback was not invoked")
except:
	testCaseException()
testCaseReport()

testCaseBegin("Verify that a paused timer does not interrupt command execution")
try:
	testCaseSetupTimerTest()

	print "Set a 2 second timer, pause it, and run a command that sleeps for 4 seconds"
	timer = twopence.Timer(2, callback = testCaseTimerCallback)
	timer.pause()
	testCaseVerifyPythonAttr(timer, "state", "paused")

	status = target.run("sleep 4")

	timer.cancel()
	testCaseVerifyPythonAttr(timer, "state", "cancelled")
	if not testCaseTimedOut():
		print "OK, callback was not invoked"
	else:
		testCaseFail("callback should not have been invoked")
except:
	testCaseException()
testCaseReport()

testCaseBegin("Verify that timer.unpause() works")
try:
	import time

	testCaseSetupTimerTest()

	print "Set a timer, pause and unpause it, and expect it to fire"
	timer = twopence.Timer(3, callback = testCaseTimerCallback)

	print "Pausing timer"
	timer.pause()

	print "Sleeping for 1 second"
	print "Unpausing timer"
	timer.unpause()
	testCaseVerifyPythonAttr(timer, "state", "active")

	remaining = timer.remaining
	if remaining >= 2.5:
		print "OK, timer.remaining=%f" % remaining
	else:
		testCaseFail("timer.remaining=%f (should be close to 3)" % remaining)

	print "Run a command that sleeps for 3 seconds"
	status = target.run("sleep 3")

	testCaseVerifyPythonAttr(timer, "state", "expired")
	testCaseVerifyPythonAttr(timer, "remaining", 0)
	if testCaseTimedOut():
		print "OK, callback was invoked"
	else:
		testCaseFail("callback was not invoked")
except:
	testCaseException()
testCaseReport()

testCaseBegin("Check whether we can cancel transactions")
try:
	cmd = twopence.Command("sleep 10", softfail = True)
	timer = twopence.Timer(2, callback = target.cancel_transactions)
	status = target.run(cmd)

	testCaseCheckStatus(status, 512 + 21)
except:
	testCaseFail("Command should have soft-failed");
	import traceback

	print traceback.format_exc(None)

testCaseReport()


testSuiteExit()
