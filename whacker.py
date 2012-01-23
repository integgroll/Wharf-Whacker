#!/usr/bin/env python
from wharfwhacker import Whacker

whacker = Whacker("1234",5,"udp",[80,443,22])

whacker.whack("172.16.2.128")