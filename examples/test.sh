#! /bin/bash

##########################################################
# Adapt the following line to your setup
#   export TARGET=virtio:/var/run/twopence/test.sock
#   export TARGET=ssh:192.168.123.45
#   export TARGET=serial:/dev/ttyS0
export TARGET= YOUR_TARGET_HERE
##########################################################

echo ""
echo "command 'ls -l'"
twopence_command $TARGET 'ls -l'
echo ""

echo "silent command 'ping -c1 8.8.8.8'"
twopence_command -q $TARGET 'ping -c1 8.8.8.8'
echo ""

echo "local 'ls -l' piped to command 'cat'"
ls -l | twopence_command $TARGET 'cat'
echo ""

echo "command 'cat' (type Ctrl-D to exit)"
twopence_command $TARGET 'cat'
echo ""

echo "command 'ls -l . /oops'"
twopence_command -o output.txt $TARGET 'ls -l . /oops'
echo "output and errors were:"
cat output.txt
rm output.txt
echo ""

echo "command 'find /tmp -type s' run as user 'nobody'"
twopence_command -u nobody -1 output.txt -2 errors.txt $TARGET 'find /tmp -type s'
echo "output was:"
cat output.txt
rm output.txt
echo "errors were:"
cat errors.txt
rm errors.txt
echo ""

echo "inject '/etc/services' => 'test.txt'"
twopence_inject $TARGET /etc/services test.txt
echo ""

echo "inject '/etc/services' => '/oops/test.txt'"
twopence_inject $TARGET /etc/services /oops/test.txt
echo ""

echo "extract 'test.txt' => 'etc_services.txt'"
twopence_extract $TARGET test.txt etc_services.txt
echo ""

echo "compare '/etc/services' with 'etc_services.txt'"
diff -q /etc/services etc_services.txt && \
  echo "files are identical"
rm etc_services.txt
echo ""

echo "extract 'oops' => 'bang'"
twopence_extract $TARGET oops bang
echo ""
rm bang
