#!/usr/bin/env python
from wharfwhacker import WharfWhacker

port_authority = WharfWhacker("172.16.2.128","1234",[443,22,80,6667],5,"udp")