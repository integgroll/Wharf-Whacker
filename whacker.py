#!/usr/bin/env python
from wharfwhacker import Whacker
import socket

whacker = Whacker("192.168.2.100","1234",[22,6667],[80,443],5)

whacker.whack("192.168.2.100")

#s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#s.sendto("are those pants?",("172.16.2.128",18))

