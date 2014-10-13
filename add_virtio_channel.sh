#! /bin/bash
# Define virtio ports in the KVM virtual machines

virsh="virsh -c qemu:///system"
list=$($virsh list --all | tail -n +3 | tr -s ' ' | cut -f 3 -d ' ')

tmpfile=$(mktemp "/tmp/add_virtio_portsXXX.xml")

function add_port
{
  socket=/var/run/twopence/${domain}.sock
  name=org.opensuse.twopence.0
  grep -q "<target type='virtio' name='${name}'/>" $tmpfile
  if [ $? -eq 0 ]; then
    echo "    Virtio port already exists in VM ${domain}"
  else
    sed -i "/<\/console>/ a\ \
   <channel type='unix'>\n\
       <source mode='bind' path='${socket}'/>\n\
       <target type='virtio' name='${name}'/>\n\
    </channel>" $tmpfile
    echo "    Virtio port added to VM ${domain}"
  fi
}

echo "Trying to add virtio ports to VMs..."
for domain in $list; do
  $virsh dumpxml $domain > $tmpfile
  add_port
  $virsh define $tmpfile > /dev/null
done

echo "Note: for running VMs, the changes will only be visible at next restart."
rm $tmpfile
