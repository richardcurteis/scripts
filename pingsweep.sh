for ip in {1..5}; do ping -c 1 -W 1 10.11.1.$ip > /dev/null && echo 10.11.1.$ip ; done
