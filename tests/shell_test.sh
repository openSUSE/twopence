#! /bin/bash
#
# Test script to exercise the shell commands.
#
# Provide a target on the command line using
#   shell_test.sh virtio:/var/run/twopence/test.sock
#   shell_test.sh ssh:192.168.123.45
#   shell_test.sh serial:/dev/ttyS0
##########################################################

TESTUSER=testuser
TESTUMASK=022

if [ $# -gt 0 ]; then
	TARGET=$1
fi

if [ -z "$TARGET" ]; then
	cat >&2 <<-EOF
	No twopence target given.
	Please specify a target as a command line argument, or
	using the TARGET environment variable.
	EOF
fi

if [ -z "$TOPDIR" ]; then
	myname=`readlink -f $0`
	TOPDIR=${myname%/tests/*}
fi
if [ -z "$LD_LIBRARY_PATH" ]; then
	export LD_LIBRARY_PATH=$TOPDIR/library
fi

overall_status=0
num_tests=0
num_succeeded=0
num_skipped=0
num_failed=0

function twopence_command {

	echo "### ../shell/command $@" >&2
	../shell/command "$@"
}

function twopence_command_background {

	echo "### ../shell/command $@" >&2
	../shell/command "$@" &
}

function twopence_inject {

	echo "### ../shell/inject $@" >&2
	../shell/inject "$@"
}

function twopence_extract {

	echo "### ../shell/extract $@" >&2
	../shell/extract "$@"
}

function test_case_begin {

	echo
	echo "### TEST: $*"

	test_case_status=0
	((num_tests++))
}

function test_case_fail {

	echo "### $*" >&2
	test_case_status=1
	overall_status=1
}

function test_case_warn {

	echo "### WARN: $*" >&2
}

function test_case_skip {

	echo "### $*" >&2
	test_case_status=skipped
}

function test_case_check_status {

	expected_status=0
	if [ $# -eq 2 ]; then
		expected_status=$2
	fi
		
	if [ "$1" -ne $expected_status ]; then
		test_case_fail "command exited with status $1"
		return 1
	fi

	return 0
}

function test_case_report {

	if [ -z "$test_case_status" ]; then
		echo "### ERROR: test_case_report called without test_case_begin" >&2
		overall_status=1
	else
		case $test_case_status in
		0)
			((num_succeeded++))
			echo "### SUCCESS";;
		skipped)
			((num_skipped++))
			echo "### SKIPPED";;
		*)
			((num_failed++))
			echo "### FAIL"
			: ;;
		esac
	fi >&2
	echo ""
	unset test_case_status
}

# Permission check tests assume that our umask is set
umask $TESTUMASK

test_case_begin "command 'ls -l /'"
twopence_command $TARGET 'ls -l /'
test_case_check_status $?
test_case_report

test_case_begin "detect server uid"
username=`twopence_command -b $TARGET 'id -un'`
if test_case_check_status $?; then
	if [ "$username" = "root" ]; then
		echo "Good, server executes commands as root by default"
	else
		test_case_fail "Server executes command as user \"$username\" by default"
	fi
fi
test_case_report

test_case_begin "run command as $TESTUSER"
username=`twopence_command -u $TESTUSER -b $TARGET 'id -un'`
if test_case_check_status $?; then
	if [ "$username" = "$TESTUSER" ]; then
		echo "Good, server executes commands as $TESTUSER as expected"
	else
		test_case_fail "Server executed command as user \"$username\" instead of $TESTUSER"
	fi
fi
test_case_report

test_case_begin "Run command 100 times just for kicks"
hostname=""
for iter in `seq 1 100`; do
	name=`twopence_command -b $TARGET 'hostname -f'`
	if ! test_case_check_status $?; then
		break
	fi

	if [ "$iter" -eq 1 ]; then
		hostname=$name
	elif [ "$hostname" != "$name" ]; then
		test_case_fail "Output of hostname -f changed during execution"
	fi
done
test_case_report


test_case_begin "silent command 'ping -c1 127.0.0.1'"
twopence_command -q $TARGET 'ping -c1 127.0.0.1'
test_case_check_status $?
test_case_report

test_case_begin "local 'ls -l' piped to command 'cat'"
ls -l /etc > expect.txt
rm -f got.txt
cat expect.txt | twopence_command -o got.txt $TARGET 'cat'
test_case_check_status $?
if [ ! -f got.txt ]; then
	test_case_fail "command didn't write output file"
elif ! cmp expect.txt got.txt; then
	test_case_fail "Files differ"
	diff -bu expect.txt got.txt
else
	echo "Good, files match"
fi
test_case_report
rm -f expect.txt got.txt

# If wildcard is not supported, the ls command should exit with an error
# because there's no file named '*'
test_case_begin "Verify that wildcarding works"
twopence_command $TARGET 'ls *' >/dev/null
test_case_check_status $?
test_case_report

test_case_begin "Verify that environment passing works"
case $TARGET in
ssh:*)	test_case_skip "Environment passing currently usually doesn't work with ssh";;
*)
	export TWOPENCE_TEST_VAR=lallaballa
	twopence_command --setenv TWOPENCE_TEST_VAR -1 stdout.txt $TARGET 'echo $TWOPENCE_TEST_VAR'
	test_case_check_status $?
	output=`cat stdout.txt`
	if [ "$output" = "$TWOPENCE_TEST_VAR" ]; then
		echo "Good, command output is \"$output\" (as expected)"
	else
		test_case_fail "unexpected output from command: $output"
	fi
	rm -f stdout.txt stderr.txt
	: ;;
esac
test_case_report

test_case_begin "Verify that environment passing works (#2)"
case $TARGET in
ssh:*)	test_case_skip "Environment passing currently usually doesn't work with ssh";;
*)
	export TWOPENCE_TEST_VAR=lallaballa
	twopence_command --setenv TWOPENCE_TEST_VAR=othervalue -1 stdout.txt $TARGET 'echo $TWOPENCE_TEST_VAR'
	test_case_check_status $?
	output=`cat stdout.txt`
	if [ "$output" = "othervalue" ]; then
		echo "Good, command output is \"$output\" (as expected)"
	else
		test_case_fail "unexpected output from command: $output"
	fi
	rm -f stdout.txt stderr.txt
	: ;;
esac
test_case_report

test_case_begin "Verify that environment passing works (#2)"
case $TARGET in
ssh:*)	test_case_skip "Environment passing currently usually doesn't work with ssh";;
*)
	test_case_begin "Verify that PATH variable passing works"
	echo "The following command should fail because of an invalid PATH setting"
	twopence_command --setenv PATH=/does/not/exist $TARGET 'ls'
	test_case_check_status $? 9
	: ;;
esac
test_case_report

test_case_begin "command 'ls -l /oops'"
twopence_command -1 stdout.txt -2 stderr.txt $TARGET 'ls -l /oops'
test_case_check_status $? 9
if [ ! -f stdout.txt ]; then
	test_case_fail "Command didn't write stdout.txt"
elif [ -s stdout.txt ]; then
	test_case_fail "Command produced standard output (should be empty)"
	cat stdout.txt
fi
if [ ! -f stderr.txt ]; then
	test_case_fail "Command didn't write stderr.txt"
elif [ ! -s stderr.txt ]; then
	test_case_fail "Command produced standard no error messages (should not be empty)"
else
	echo "Command produced the following error message"
	cat stderr.txt
fi
test_case_report
rm -f stdout.txt stderr.txt

##################################################################
# Do a find(1) in a directory that we know contains subdirectories
# not accessible to the test user
test_case_begin "command 'find /etc -type s' run as user '$TESTUSER'"
twopence_command -u $TESTUSER -1 output.txt -2 errors.txt $TARGET 'find /etc -type s'
test_case_check_status $? 9
echo "output was:"
cat output.txt
rm output.txt
echo "errors were:"
cat errors.txt
rm errors.txt
test_case_report
rm -f  errors.txt output.txt

server_test_file=/tmp/twopence-test.txt

test_case_begin "cleanup: remove $server_test_file"
twopence_command $TARGET "rm -f $server_test_file"
test_case_check_status $?
test_case_report

test_case_begin  "inject '/etc/services' => '$server_test_file'"
twopence_inject $TARGET /etc/services $server_test_file
test_case_check_status $?
test_case_report

test_case_begin "inject '/etc/services' => '/oops/test.txt'"
twopence_inject $TARGET /etc/services /oops/test.txt
if [ $? -eq 0 ]; then
	test_case_fail "command exited with status 0; should have flagged an error"
fi
test_case_report

#
# This doesn't really belong here, but OTOH we need to run python with a
# specific stdin...
#
test_case_begin "ensure that running commands through python will also read from stdin"
cat >/tmp/twopence-test.py <<EOF
import twopence
import sys

target = twopence.Target("$TARGET");
target.run("cat")
EOF

teststring="imadoofus"
echo $teststring | python /tmp/twopence-test.py | (
	read foo
	if [ -z "$foo" ]; then
		echo "No output from command"
		exit 1
	fi
	if [ "$foo" != "$teststring" ]; then
		echo "Unexpected output from command"
		echo "--<<<--"
		echo $foo
		echo "-->>>--"
		echo "Expected \"$teststring\""
		exit 1
	fi

	echo "Good, received expected output \"$teststring\""
	exit 0
)
test_case_check_status $?
test_case_report
rm -f /tmp/twopence-test.py

test_case_begin "extract '$server_test_file' => 'etc_services.txt'"
twopence_extract $TARGET $server_test_file etc_services.txt
test_case_check_status $?
if ! cmp /etc/services etc_services.txt; then
	test_case_fail "/etc/services and etc_services.txt differ"
	diff -u /etc/services etc_services.txt | head -50
fi

have_perms=`stat -c 0%a etc_services.txt`
let want_perms="0666 & ~$TESTUMASK"
want_perms=`printf "0%o" $want_perms`
if [ $have_perms -ne $want_perms ]; then
	test_case_fail "etc_services.txt has unexpected permissions $have_perms (wanted $want_perms)"
fi
rm -f etc_services.txt
test_case_report

test_case_begin "make sure inject truncates the uploaded file"
echo "a" > short_file
twopence_inject $TARGET short_file $server_test_file
twopence_command -o cat_file $TARGET "cat $server_test_file"
test_case_check_status $?
if ! cmp cat_file short_file; then
	test_case_fail "file mismatch when re-downloading short_file"
	echo "Lines of text in each file:"
	wc -l short_file
	wc -l cat_file
fi
rm -f short_file cat_file
test_case_report


test_case_begin "upload a zero length file"
twopence_inject $TARGET /dev/null $server_test_file
twopence_command -o cat_file $TARGET "cat $server_test_file"
test_case_check_status $?
if test -s cat_file; then
	test_case_fail "zero length file is no longer empty after extraction"
	wc -l cat_file
fi
rm -f cat_file
test_case_report

test_case_begin "upload a file as user $TESTUSER"
twopence_command $TARGET "rm -f $server_test_file"
test_case_check_status $?

twopence_inject -u $TESTUSER $TARGET /dev/null $server_test_file
if test_case_check_status $?; then
	username=`twopence_command -b $TARGET "stat --format %U $server_test_file"`
	if [ "$username" != "$TESTUSER" ]; then
		test_case_fail "wrong file owner \"$username\", expected user $TESTUSER"
	else
		echo "Good, file is owned by user $TESTUSER"
	fi
fi
test_case_report


test_case_begin "extract 'oops' => 'bang'"
twopence_extract $TARGET oops bang
test_case_check_status $? 7
rm -f bang
test_case_report

test_case_begin "extract a directory (should fail)"
twopence_extract $TARGET /etc extracted
test_case_check_status $? 7
rm -f extracted
test_case_report

test_case_begin "extract an empty file"
twopence_command $TARGET "touch /tmp/twopence-test-empty-file"
twopence_extract $TARGET /tmp/twopence-test-empty-file extracted
test_case_check_status $? 0
if [ ! -e extracted ]; then
	test_case_fail "downloaded file does not exist"
elif [ -s extracted ]; then
	test_case_fail "downloaded file is not empty"
fi
twopence_command $TARGET "rm -f /tmp/twopence-test-empty-file"
rm -f extracted
test_case_report


test_case_begin "extract a proc file"
case $TARGET in
ssh:*)	test_case_skip "Extracting /proc files currently does not work with ssh";;
*)
	twopence_extract $TARGET /proc/interrupts extracted
	test_case_check_status $? 0
	if [ -e extracted -a ! -s extracted ]; then
		test_case_fail "downloaded file is empty"
	else
		echo "good, extracted file has `wc -l < extracted` lines"
	fi
	rm -f extracted
esac
test_case_report

# Run a command that takes longer than the timeout of 10 seconds.
# This should exit with a timeout error.
# As a bonus, the total time spent executing this should not be
# less than the timeout, and shouldn't exceed the expected timeout
# by too much. The latter cannot be guaranteed, especially if we should
# ever run this as part of the build validation in OBS, so we make that
# check a warning only.
#
test_case_begin "test timeout of commands"
t0=`date +%s`
twopence_command --timeout 10 $TARGET "sleep 11"
test_case_check_status $? 8
t1=`date +%s`
let elapsed=$t1-$t0
if [ $elapsed -lt 10 ]; then
	test_case_fail "test case took $elapsed seconds to complete (should be at least 10)"
elif [ $elapsed -gt 12 ]; then
	test_case_warn "test case took $elapsed seconds to complete (should be close to 10)"
fi
test_case_report

# Run a command that takes almost as long as the timeout of 10 seconds.
# This should exit normally and not time out.
# The total time spent executing the command is verified like above.
#
test_case_begin "test timeout of commands #2"
t0=`date +%s`
twopence_command --timeout 10 $TARGET "sleep 9"
test_case_check_status $?
t1=`date +%s`
let elapsed=$t1-$t0
if [ $elapsed -lt 9 ]; then
	test_case_fail "test case took $elapsed seconds to complete (should be at least 9)"
elif [ $elapsed -gt 11 ]; then
	test_case_warn "test case took $elapsed seconds to complete (should be close to 9)"
fi
test_case_report

# Run a command that takes longer than the default keepalive timeout.
# This should "just work"
test_case_begin "making sure that link keepalives are delivered"
case $TARGET in
ssh:*)	test_case_skip "Keepalives are not available with ssh; so no testing them";;
*)	twopence_command --timeout=120 $TARGET "sleep 65"
	test_case_check_status $? 0
esac
test_case_report

# Run a command that takes longer than the default keepalive timeout, and disable
# sending of keepalives on the client side (the magic keepalive value of "-2" is
# just for testing purposes).
# This should cause the server to close the connection due to inactivity.
test_case_begin "make sure that the server drops the link in the absence of keepalives"
case $TARGET in
ssh:*)	test_case_skip "Keepalives are not available with ssh; so no testing them";;
*)	twopence_command --keepalive=-2 --timeout=120 $TARGET "sleep 65"
	test_case_check_status $? 8
esac
test_case_report


test_case_begin "test SIGINT handling"
t0=`date +%s`
twopence_command_background $TARGET "sleep 5"
pid=$!
sleep 1
echo "Sending SIGINT to $pid"
ps hup $pid
kill -INT $pid
wait $pid
test_case_check_status $? 9
t1=`date +%s`
let elapsed=$t1-$t0
if [ $elapsed -ge 5 ]; then
	test_case_warn "test case took $elapsed seconds to complete (looks like we waited for the command to finish)"
fi
test_case_report

test_case_begin "make sure server side command is gone after signalling"
twopence_command_background -u $TESTUSER $TARGET "sleep 20"
pid=$!
sleep 1
echo "Sending SIGINT to $pid"
ps hup $pid
kill -INT $pid
wait $pid
test_case_check_status $? 9

sleep 1
echo "Checking if the command is still running"
if twopence_command $TARGET "ps aux" | grep "^testuser.*sleep 20$"; then
	case $TARGET in
	ssh:*)
		test_case_warn "command is still running"
		echo "For ssh, this is expected, unfortunately";;
	*)
		test_case_fail "command is still running"
	esac
else
	echo "Good, the command is no longer running on the server"
fi
test_case_report

cat<<EOF
### SUMMARY $num_tests $num_skipped $num_failed 0
Total tests run: $num_tests
Succeeded:       $num_succeeded
Skipped:         $num_skipped
Failed:          $num_failed

Overall status is $overall_status
EOF
exit $overall_status

