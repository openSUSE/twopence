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

test_case_begin "command 'find /dev -type s' run as user '$TESTUSER'"
twopence_command -u $TESTUSER -1 output.txt -2 errors.txt $TARGET 'find /dev -type s'
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

test_case_begin "extract '$server_test_file' => 'etc_services.txt'"
twopence_extract $TARGET $server_test_file etc_services.txt
test_case_check_status $?
if ! cmp /etc/services etc_services.txt; then
	test_case_fail "/etc/services and etc_services.txt differ"
	diff -u /etc/services etc_services.txt | head -50
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

test_case_begin "test timeout of commands"
t0=`date +%s`
twopence_command --timeout 10 $TARGET "sleep 11"
test_case_check_status $? 8
t1=`date +%s`
let elapsed=$t1-$t0
if [ $elapsed -lt 10 -o $elapsed -gt 11 ]; then
	test_case_fail "test case took $elapsed seconds to complete (expected to be between 10 and 11 secs)"
fi
test_case_report

test_case_begin "test timeout of commands #2"
t0=`date +%s`
twopence_command --timeout 10 $TARGET "sleep 9"
test_case_check_status $?
t1=`date +%s`
let elapsed=$t1-$t0
if [ $elapsed -lt 9 -o $elapsed -gt 10 ]; then
	test_case_fail "test case took $elapsed seconds to complete (expected to be between 9 and 10 secs)"
fi
test_case_report

test_case_begin "test SIGINT handling"
twopence_command_background $TARGET "sleep 5"
pid=$!
sleep 1
echo "Sending SIGINT to $pid"
ps hup $pid
kill -INT $pid
wait $pid
test_case_check_status $? 9
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

