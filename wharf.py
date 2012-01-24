#!/usr/bin/env python
from wharfwhacker import WharfWhacker

#Syntax for use of WharfWhacker server
# WharfWhacker(local IP address, password for connecting, array of ports in use, number of knocks needed for verification)

port_authority = WharfWhacker("172.16.2.128","1234",[443,22,80,6667],5)