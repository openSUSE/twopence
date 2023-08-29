#! /bin/bash

##########################################################
# Adapt the following line to your setup
#   export TARGET=virtio:/run/twopence/test.sock
#   export TARGET=ssh:192.168.123.45
#   export TARGET=serial:/dev/ttyS0
export TARGET= YOUR_TARGET_HERE
##########################################################

if [ "$TARGET" = "" ]; then
  cat <<END
This shell script is meant as an example from which you could
copy and paste your own test scripts.

1 - copy this script to your home directory;
2 - modify it to declare \$TARGET variable;
3 - run it to see how it works;
4 - get your inspiration from the source code.

END
  exit 1
fi

# We can send a command to the system under tests
echo "twopence_command $TARGET 'ls -l'"
twopence_command $TARGET 'ls -l'
echo ""

# We can avoid displaying the results
echo "twopence_command -q $TARGET 'ping -c1 8.8.8.8'"
twopence_command -q $TARGET 'ping -c1 8.8.8.8'
echo ""

# We can avoid displaying the error codes
echo "twopence_command -b $TARGET 'uname -a'"
twopence_command -b $TARGET 'uname -a'
echo ""

# We can pipe a local command
# to another command on the remote system
echo "ls -l | twopence_command $TARGET 'cat'"
ls -l | twopence_command $TARGET 'cat'
echo ""

# We can work interactively with the remote system
echo "twopence_command -t 15 $TARGET 'cat'"
echo "(type Ctrl-D to exit, Ctrl-C to end)"
twopence_command -t 15 $TARGET 'cat'
echo ""

# We can redirect remote standard output and error to the same file
echo "twopence_command -o output.txt $TARGET 'ls -l . /oops'"
twopence_command -o output.txt $TARGET 'ls -l . /oops'
echo "output and errors were:"
cat output.txt
rm output.txt
echo ""

# We can redirect remote standard output and error to separate files
echo "twopence_command -u nobody -1 output.txt -2 errors.txt $TARGET 'find /tmp -type f'"
twopence_command -u nobody -1 output.txt -2 errors.txt $TARGET 'find /tmp -type f'
echo "output was:"
cat output.txt
rm output.txt
echo "errors were:"
cat errors.txt
rm errors.txt
echo ""

# We can inject a local file into the remote system
echo "twopence_inject $TARGET /etc/services test.txt"
twopence_inject $TARGET /etc/services test.txt
echo ""

# We can extract a file from the remote system
# and store it locally
echo "extract 'test.txt' => 'etc_services.txt'"
twopence_extract $TARGET test.txt etc_services.txt
rm etc_services.txt
echo ""
