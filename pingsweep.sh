 for ip in {1..255}; do ping -c 1 -W 1 $0.$ip >> /dev/null && echo $0.$ip ; done
