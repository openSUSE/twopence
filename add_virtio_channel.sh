#! /bin/bash
# Define virtio ports in some KVM virtual machine
#
# Usage: ./add_virtio_channel domain 

virsh="virsh -c qemu:///system"
list=$($virsh list --all --name)

function usage
{
  echo "Usage:"
  echo "    $0 <domain>"
  echo
  echo "Currently defined domains are:"
  echo "$list" | sed 's/^/    /'
  echo
  exit 1
}

[ $# -eq 1 ] || usage
[ "$1" != "" ] || usage
[[ "$list" =~ "$1" ]] || usage
domain="$1"

function add_port
{
  socket=/run/twopence/${domain}.sock
  name=org.opensuse.twopence.0
  grep -q "<target type='virtio' name='${name}'/>" $tmpfile
  if [ $? -eq 0 ]; then
    echo "Error: virtio port already exists in VM \"${domain}\""
    echo
  else
    sed -i "/<devices>/ a\ \
   <channel type='unix'>\n\
       <source mode='bind' path='${socket}'/>\n\
       <target type='virtio' name='${name}'/>\n\
    </channel>" $tmpfile
    echo "Virtio port added to VM \"${domain}\""
    echo "Note: for a running VM, the changes will only be visible at next restart."
    echo
  fi
}

echo "Trying to add virtio ports to VM \"${domain}\"..."
echo
tmpfile=$(mktemp "/tmp/add_virtio_portsXXX.xml")
$virsh dumpxml $domain > $tmpfile
add_port
$virsh define $tmpfile > /dev/null
rm $tmpfile
