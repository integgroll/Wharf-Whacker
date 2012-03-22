#!/usr/bin/env python
from wharfwhacker import Whacker
import sys
auth_token = ""
if len(sys.argv) == 2:
  auth_token = sys.argv[1]

whacker = Whacker()

whacker.whack("127.0.0.1",auth_token)