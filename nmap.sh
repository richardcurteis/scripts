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
    $mkdir -p $hostname/foothold
    $mkdir -p $hostname/priv_esc
    $mkdir -p $hostname/post_exploit

    # Nmap 
    $nmap -sS -sC -sV --version-all -A -O -p- -oA $hostname/nmap/initial $ip
    $nmap -sU -F -oA $hostname/nmap/udp/common_udp_ports $ip
  fi
# End of loop
done
