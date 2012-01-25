#!/usr/bin/env python
from wharfwhacker import WharfWhacker

#Syntax for use of WharfWhacker server
# WharfWhacker(local IP address, password for connecting, array of ports in use, number of knocks needed for verification)

port_authority = WharfWhacker("192.168.2.100","1234",[22,6667],[443,80],5)
port_authority.start()
