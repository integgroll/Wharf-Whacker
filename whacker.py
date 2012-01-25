#!/usr/bin/env python
from wharfwhacker import Whacker
import socket

ip_address = "172.16.2.158"
whacker = Whacker(ip_address,"1234",[22,6667],[80,443],5)

whacker.whack(ip_address)

#s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#s.sendto("are those pants?",(ip_address,18))

