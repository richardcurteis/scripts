#!/usr/bin/bash 

nmap="/usr/bin/nmap"
mkdir="/usr/bin/mkdir"
cd /root/pwk/labs

for host in $(cat $1)
ip=${echo $host | grep ":" | cut -d ":" -f 2}
hostname=${echo $host | grep "." | cut -d "." -f 1}
do
  if [ ! -d $ip ]; then
    $mkdir $host
    $mkdir $ip/nmap
    $mkdir $ip/nmap/udp
  fi
  # Nmap 
  $nmap -sS-sC -sV --version-intensity=9 -A -O -p- -oA $host/nmap/initial $ip
  $nmap -sU -sC -sV --version-intensity=9 -p- -oA $host/nmap/udp/initial_udp $ip
# End of loop
done
