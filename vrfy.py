#!/usr/bin/python

import socket 
import sys

# Still needs to be tested in labs

if len(sys.argv) != 2:
    print "Usage: vrfy.py <ip_list> <user_list>"

ip_list = open(sys.argv[1], "r")
name_list = open(sys.argv[2], "r")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

while True:
    for ip in ip_list:
        ip = ip.rstrip()
        for name in name_list:
            name = name.rstrip()
            if len(ip) <= 1 or len(name) >= 0:
                pass
            try:
                connect = s.connect((ip, 25))
                banner = s.recv(1024)
                print banner.send('VRFY ' + name + '\r\n')
                results = s.recv(1024)
                print results
                s.close()
            except Exception as e:
                s.close()
                pass
