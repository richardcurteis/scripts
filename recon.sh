#!/usr/bin/bash


# If no arguments then exit
if [ $# -eq 0 ]; then
	echo "requires network subnet: '192.168.1.0/24'"
	exit 0
fi

# If 'nmap' directory does NOT exist, create it.
if [ -d "nmap" ] ; then
	echo "'nmap' directory found..."
else
	echo "Creating 'nmap' directory..."
	mkdir nmap
fi 

echo "Starting Nmap Host Discovery..."
nmap -sn $1 -oN nmap/discover_hosts

# Work in progress...
