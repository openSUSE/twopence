# What is it

Twopence is a test executor
* it can run tests in a KVM virtual machine without using the network
* it can also run more traditional SSH tests in a remote machine
* it can send the tests through a serial cable too

## How does it work

* Twopence is basically a set of libraries
* Shell, Ruby and Python wrappers are provided for convenience
* each library is seen as a plugin
* currently available plugins are virtio (KVM), SSH, serial, and TCP

## How would I use it

Have a look at the examples:

* [from the shell](examples/example.sh)
* [from Ruby](examples/example.rb)
* [from Python](examples/example.py)

## A note on security

* the test server runs on the system under test as root, performs no authentication,
  and will execute whatever command it is asked to
* the SSH tests assume that you have published a public key
  with a private key without passphrase
* in short, Twopence is very unsafe and should be reserved to
  pure test environments (test labs, no production servers)

## How do I build it

### Prerequisites

```bash
# Gems
gem install rake-compiler

# openSUSE Leap/Tumbleweed and SLE
zypper install gcc libssh-devel ruby-devel python-devel

# Ubuntu
apt-get install gcc libssh-dev ruby-dev rake-compiler python-dev

# Fedora
dnf install gcc libssh-devel ruby-devel rubygem-rake-compiler python-devel redhat-rpm-config
```

### Build and installation

```bash
# as normal user execute
make

# as root execute
make install
ldconfig
```

## How do I run the examples with SSH

* on the system under test, make sure the sshd daemon is started:

```bash
service sshd start
```

and that it is not being blocked by the firewall

* on the testing system, create a pair of SSH keys:

```bash
ssh-keygen -t rsa
```

without setting a passphrase

* copy the public key to the system under test:

```bash
scp ~/.ssh/id_rsa.pub joe@sut.example.com:.
```

* then, on the system under test, append the public key to the
  authorized keys file:

```bash
cat id_rsa.pub >> ~/.ssh/authorized keys
```

* repeat for each account that will be used to run the tests
* in the directory `/usr/local/lib/twopence/`
  adapt the first lines of `test.rb` and `test.s`h to the IP address
  or hostname of your system under test
* run the following commands:

```bash
cd examples
/usr/local/lib/twopence/test.sh
ruby /usr/local/lib/twopence/test.rb
```

## How do I run the examples with virtio

* setup a KVM virtual machine
* declare a UNIX domain socket
* to do that, you can use virt-manager:
  Hardware => Channel =>
  Path = the directory and name of your socket file
  Target type = virtio
  Target name = org.opensuse.twopence.0
* or you can use the provided script:

```bash
/usr/local/lib/twopence/add_virtio_channel.sh mydomain
```

* start the VM
* copy the test server into the VM:

```bash
scp /usr/local/lib/twopence/twopence_test_server root@sut.example.com:.
```

instead of scp, you may use shared folders or whichever method you prefer

* inside of the VM, run the server as root:

```bash
./twopence_test_server
```

* in the directory `/usr/local/lib/twopence/`
  adapt the first lines of `test.rb` and `test.sh`
  to the name of the socket file you just created; for example:

```bash
export TARGET=virtio:/run/twopence/test.sock
```

* run the following commands:

```bash
cd examples
export LD_LIBRARY_PATH=../library
ruby /usr/local/lib/twopence/test.rb
```

* if you get errors opening the communication,
  check the permissions of the socket file:

```bash
ls -l /run/twopence/test.sock
```

## How do I run the examples with a serial cable

* connect a null-modem cable to the system under test
* connect the other end to the testing machine
* determine the port name on both ends
  (you can use "minicom" to do that)
* copy the test server into the system under test:

```bash
scp /usr/local/lib/twopence/twopence_test_server root@sut.example.com:.
```

instead of scp, you may use shared folders or whichever method you prefer

* inside of the sut, run the server as root:

```bash
./twopence_test_server
```

* in the directory `/usr/local/lib/twopence/`
  adapt the first lines of test.rb and test.sh
  to the name of the character device; for example:

```bash
export TARGET=serial:/dev/ttyS0
```

* run the following commands:

```bash
cd examples
/usr/local/lib/twopence/test.sh
ruby /usr/local/lib/twopence/test.rb
```

* if you get errors opening the communication,
  check the permissions of the character device file:

```bash
ls -l /dev/ttyS0
```
