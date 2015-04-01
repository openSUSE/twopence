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

targetSpec = None
if len(sys.argv) > 1:
	targetSpec = sys.argv[1]
if not targetSpec:
	print "Expected twopence target as argument"
	sys.exit(1)

target = twopence.Target(targetSpec);

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

def testCaseException():
	info = sys.exc_info()
	testCaseFail("caught python exception %s: %s" % info[0:2])
	traceback.print_tb(info[2])

def testCaseReport():
	global testCaseStatus, testCaseRunning, numFailed

	if testCaseStatus:
		print "### " + testCaseStatus
		numFailed = numFailed + 1
	else:
		print "### SUCCESS"
	print

	testCaseRunning = False

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

	sys.exit(exitStatus)

##################################################################
# Individual test cases start here
##################################################################

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
	testCaseCheckStatus(status, 9)
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

testCaseBegin("run a command procuding lots of output")
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

testCaseBegin("run /bin/pwd in the background")
try:
	cmd = twopence.Command("/bin/pwd", background = 1);
	if target.run(cmd):
		testCaseFail("Target.run() of a backgrounded command should return None")
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
testCaseReport()

testCaseBegin("run several processes in the background")
try:
	cmds = []
	for time in range(6, 0, -1):
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

	if nreaped != 6:
		testCaseFail("Reaped %d commands, expected 6" % nreaped)
except:
	testCaseException()
testCaseReport()

# There's a "line timeout" in the ssh target plugin that wreaks havoc with the regular
# timeout handling.
# If that problem is still present, the following will result in a python exception
# from target.run()
testCaseBegin("Verify long command timeout")
try:
	import time

	print "The next command should sleep for 65 seconds"

	t0 = time.time()
	st = target.run("sleep 65", timeout = 120)
	delay = time.time() - t0

	if delay < 65:
		testCaseFail("command slept for less than 65 seconds (only %u sec)" % delay)
	elif delay > 67:
		testCaseFail("command slept for way more than 65 seconds (overall %u sec)" % delay)
	else:
		print "Good: Slept for %u seconds" % delay
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


testSuiteExit()
