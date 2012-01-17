#!/usr/bin/env python
from scapy.all import *
import hashlib
from time import strftime, gmtime, sleep
from Queue import Queue
from threading import Thread
password = "1234"
ipaddress = "124.124.124.124"

def port_checker(password,ipaddress):
  ports=[]
  porthash = hashlib.sha512(password+strftime("%Y - %j - %d - %H - %M",gmtime())).hexdigest()
  x = 0
  while len(ports) < 1 :
    temp_port = int(porthash[x:x+4],16)
    if temp_port > 1024:
      ports.append(temp_port)
    x = x + 5
  porthash = hashlib.sha512(ipaddress + password+strftime("%Y - %j - %d - %H - %M",gmtime())).hexdigest()  
  x=0
  while len(ports) < 10 + 1 :
    temp_port = int(porthash[x:x+4],16)
    if temp_port > 1024:
      ports.append(temp_port)
    x = x + 5      
  return ports
  
ports = port_checker(password,ipaddress)

for i in ports:
  a = IP(src=ipaddress,dst="123.123.123.123")/TCP(dport=i)
  print a['IP']['TCP'].dport 
  send(a)
  
ipaddress = "124.124.124.234"
ports = port_checker(password,ipaddress)

for i in ports:
  a = IP(src=ipaddress,dst="123.123.123.123")/TCP(dport=i)
  print a['IP']['TCP'].dport 
  send(a)  
  

  