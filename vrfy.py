#!/usr/bin/python

import socket
import sys

if len(sys.argv) != 2:
    print "Usage: vrfy.py <ip_list> <user_list>"

with open(sys.argv[0]) as ip_list, open(sys.argv[1]) as name_list:
    for ip in ip_list:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connect = s.connect((ip, 25))
        for name in name_list:
            banner = s.recv(1024)
            print banner.send('VRFY ' + name + '\r\n')
            results = s.recv(1024)
            print results
        s.close()
