#!/usr/bin/bash 

nmap="/usr/bin/nmap"
mkdir="/usr/bin/mkdir"
cd /root/pwk/labs

for host in $(cat $1)
ip=${echo $host | grep ":" | cut -d ":" -f 2}
hostname=${echo $host | grep "." | cut -d "." -f 1}
do
  if [ ! -d $ip ]; then
    $mkdir -p $hostname/nmap/udp

    # Nmap 
    $nmap -sS -sC -sV --version-all -A -O -p- -oA $hostname/nmap/initial $ip
    $nmap -sU -sV  -F -oA $hostname/nmap/udp/common_udp_ports $ip
  fi
# End of loop
done
