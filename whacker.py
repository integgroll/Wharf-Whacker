#!/usr/bin/env python
from wharfwhacker import Whacker
import socket

whacker = Whacker()

whacker.whack("127.0.0.1")

#s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#s.sendto("are those pants?",(ip_address,18))

