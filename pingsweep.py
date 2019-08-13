#!/usr/bin/python

from netaddr import IPNetwork
import os

for ip in IPNetwork('10.11.1.0/24'):
	ip = str(ip)
	response = os.system('ping -c 1 ' + ip + ' | grep "bytes from" | cut -d " " -f 4 | cut -d ":" -f 1 &')
	if response != 0:
		print(ip)
