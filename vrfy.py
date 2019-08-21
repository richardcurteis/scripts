#!/usr/bin/python

import socket 
import sys

if len(sys.argv) != 2:
    print "Usage: vrfy.py <user_list> <ip_list>"

for name in open(sys.argv[1]):
    for ip in open(sys.argv[2]):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connect = s.connect((ip, 25))
        banner = s.recv(1024)
        print banners.send('VRFY ' + name + '\r\n')
        results = s.recv(1024)
        print results
        s.close()
