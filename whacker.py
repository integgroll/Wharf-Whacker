#!/usr/bin/env python
from wharfwhacker import Whacker

whacker = Whacker("1234",5,"tcp",[80,443,22])

whacker.whack("123.123.123.123")