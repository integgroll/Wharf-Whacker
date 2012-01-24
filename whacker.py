#!/usr/bin/env python
from wharfwhacker import Whacker
import socket

whacker = Whacker("1234",[80,443,22],5,"udp")

whacker.whack("172.16.2.128")

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto("are those pants?",("172.16.2.128",18))

