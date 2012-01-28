#!/usr/bin/env python
import socket
import SocketServer
import signal
import sys
import subprocess
import hashlib
import re
import os
import logging
from time import strftime, gmtime, sleep
from Queue import Queue
from threading import Thread

class WharfWhacker:
  def __init__(self, config_file = "wharfwhacker.conf"):
    attributes = dict()

    if os.path.isfile(config_file):
      conf = file(config_file,"r").readlines()
      for line in conf:
        line = line.rstrip()
        if len(line)>0:
          if line[0] not in ["\n","#"]:
            temp = line.split(":")
            attributes[temp[0]] = temp[1].lstrip()

    self.ip_address = attributes['server_address']
    self.password = attributes['password']
    self.secured_ports = attributes['protect_ports'].split(",")
    self.safe_ports = attributes['ignore_ports'].split(",")
    self.whack_threshhold = int(attributes['whack_threshhold'])
    self.ignore_ports = self.secured_ports + self.safe_ports
    self.authentication_length = int(attributes['knocks'])
    self.start_port = 0
    self.reserved_pool = ThreadPool(self.authentication_length*10+1)
    self.connection_sockets = []
    self.connections = dict()
    self.ban_list = dict()
        
  def start(self):
    #iptables set for WharfWhacker, the readme explains this.
    subprocess.call("iptables -N WharfWhacker" , shell = True)
    subprocess.call("iptables -N WharfWhacked" , shell = True)
    self.add_iptable_rule("INPUT -p udp -j WharfWhacked")
    self.add_iptable_rule("WharfWhacker -p tcp -j DROP")
    self.add_iptable_rule("WharfWhacked -p udp -j ACCEPT")
    for i in self.secured_ports:
      self.add_iptable_rule("INPUT -p tcp --destination-port " + str(i) + " -j WharfWhacker")

    self.reserved_pool.add_task(self.new_ports)    
    while True:    
      pass      
    
  def new_ports(self):
    # This section is developing which ports to use. <- Pro commenting skills bro, no srsly
    while True:
      self.start_port = 0
      self.connections = dict()
      #Generates the new start port and opens it up for reading
      self.generate_initial_port()
      self.reserved_pool.add_task(self.stream_reader,self.start_port)
      #Waits until the start of a new minute
      sleep((60-int(strftime("%S"))))
      #Culls the start socket, and the other sockets created over the past minute due to connection attempts
      for sock in self.connection_sockets:
        sock.shutdown()
      self.connection_sockets = []
        
  def generate_initial_port(self):
    # Uses the porthash that was generated
    porthash = hashlib.sha512(self.password+strftime("%Y - %j - %d - %H - %M",gmtime())).hexdigest()
    x=0
    while self.start_port == 0 :
      temp_port = int(porthash[(x%512):((x+4)%512)],16)
      if temp_port > 1024 and temp_port not in self.ignore_ports:
        self.start_port = temp_port
      x = x + 5

  def check_ports(self,ip_address,port): 
    # Logic hell that deals with the ports, and where they are at in the authentication sequence
    if ip_address in self.connections:
      if self.connections[ip_address][self.connections[ip_address][0]] == port:
        #Correct port hit
        self.connections[ip_address][0] = self.connections[ip_address][0] + 1
        if self.connections[ip_address][0] >= self.authentication_length + 1:
          #Fully Authenticated
          ## log so and so ip has been correctly authed, log away
          self.allow_ip(ip_address)
          del self.connections[ip_address]
      else:
        #Incorrect port hit
        self.ban_check(ip_address)
        del self.connections[ip_address]
    else:
      if self.start_port==port:
        #Correct start port, creates sockets for other ports
        ## log the correct port has been started on said IP
        self.connections[ip_address] = [1]
        self.generate_secure_ports(ip_address)
      else:
        if port not in self.safe_ports:
          #totally wrong, nuke the hell out of it with the ban list
          #print "Failcamp - banlisting"
          self.ban_ip(ip_address)
          del self.connections[ip_address]
          self.ban_check(ip_address)

  def generate_secure_ports(self,ip_address):
    # This is the function that you need to change to generate a list of ports to knock against
    porthash = hashlib.sha512(ip_address + self.password+strftime("%Y - %j - %d - %H - %M",gmtime())).hexdigest()  
    x = 0
    while len(self.connections[ip_address]) < self.authentication_length + 1 :
      temp_port = int(porthash[x:x+4],16)
      if temp_port > 1024 and temp_port not in self.ignore_ports:
        self.connections[ip_address].append(temp_port)    
      x = x + 5
    for port in self.connections[ip_address]:
      self.reserved_pool.add_task(self.stream_reader,port)
      
  def stream_reader(self,port):
    # Creates a WharfServer to listen on a specific port
    self.connection_sockets.append(WharfServer((self.ip_address,port),InitialUDPHandler,self))
    self.connection_sockets[-1].serve_forever()

  def allow_ip(self,ip_address):
    # Where the IPTables code will go
    self.add_iptable_rule("WharfWhacker -p tcp --source " + ip_address + " -j ACCEPT")
    
  def ban_ip(self,ip_address):
    # Bans an IP
    self.add_iptable_rule("WharfWhacked -p udp --source " + ip_address + " -j DROP")
        
  def add_iptable_rule(self,rule):
    # Sadly I have to do it like this so that there are no duplicate rules
    # Seriously bro, you have to come up with a different way to do this it is rather chumpy and you know it.
    subprocess.call("iptables -D " + rule , shell = True)
    subprocess.call("iptables -I " + rule , shell = True)

  def ban_check(self,ip_address):
    # Applying the attempts until ban functions
    if ip_address in self.ban_list:
      self.ban_list[ip_address] = self.ban_list[ip_address] + 1
      if self.ban_list >= self.whack_threshhold:
        self.ban_ip(ip_address)
    else:
      self.ban_list[ip_address] = 1
      
  
#WharfWhacker Class is ended here    


class Whacker():
  def __init__(self, config_file = "wharfwhacker.conf"):
    attributes = dict()
    if os.path.isfile(config_file):
      conf = file(config_file,"r").readlines()
      for line in conf:
        line = line.rstrip()
        if len(line)>0:
          if line[0] not in ["\n","#"]:
            temp = line.split(":")
            attributes[temp[0]] = temp[1].lstrip()
    self.ip_address = attributes['local_ip']
    self.password = attributes['password']
    self.secured_ports = attributes['protect_ports'].split(",")
    self.safe_ports = attributes['ignore_ports'].split(",")
    self.authentication_length = int(attributes['knocks'])
    self.ignore_ports = self.secured_ports + self.safe_ports
    self.ports = []
    
  def whack(self,target_ip):
    self.generate_ports()
    # Runs a knock against target server
    for i in self.ports:
      #print i
      s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      s.sendto("are those pants?",(target_ip,i))
      #We have to sleep here because most servers can't run the hashes for the ip's
      #AND open new sockets in the time before the next packet shows up.
      sleep(0.1)
    print "Knock Complete, check for entry"
  def generate_ports(self):
    # Generates the ports that the knock will use.
    #Initial port to knock on
    porthash = hashlib.sha512(self.password+strftime("%Y - %j - %d - %H - %M",gmtime())).hexdigest()
    x = 0
    while len(self.ports) < 1 :
      temp_port = int(porthash[x:x+4],16)
      if temp_port > 1024 and temp_port not in self.ignore_ports:
        self.ports.append(temp_port)
      x = x + 5
    #Ports that are based on the IP
    porthash = hashlib.sha512(self.ip_address + self.password+strftime("%Y - %j - %d - %H - %M",gmtime())).hexdigest()  
    x=0
    while len(self.ports) < self.authentication_length + 1 :
      temp_port = int(porthash[x:x+4],16)
      if temp_port > 1024 and temp_port not in self.ignore_ports:
        self.ports.append(temp_port)
      x = x + 5  
#Whacker Class is ended here

#The following four classes are all part of the setup so that the other things can run happily.
#The following two classes are part of the setup so that the handlers that hold the SocketServers 
#can access the classes that they are supposed to so they can actually check and ensure ports are 
#accessed in the correct order by the correct IP.
class WharfServer(SocketServer.UDPServer):
  def __init__(self, address, handler, wharf):
    self.wharf = wharf
    SocketServer.UDPServer.__init__(self, address, handler)
# WharfServer Class is ended here

class InitialUDPHandler(SocketServer.BaseRequestHandler):
  def handle(self):
    data = self.request[0].strip()
    ip,port = self.request[1].getsockname()
    self.client_address
    self.server.wharf.check_ports(ip,port)
# InitialUDPHandler Class is eneded here

#The following two classes are used to create threads for different functions so I dont have to have
#premade functions for all of my threading classes
# Basic Use
# pool = ThreadPool(number of posible threads)
# pool.add_task(function, all , the , parameters , for , said , function)
# pool.add_task(other_function, its , parameters)
class Worker(Thread):
  """Thread executing tasks from a given tasks queue"""
  def __init__(self, tasks):
    Thread.__init__(self)
    self.tasks = tasks #refer this worker to the shared Job Queue
    self.setDaemon(True)
    self.start()
  
  def run(self):
    while True:
      func, args, kargs = self.tasks.get()
      try: func(*args, **kargs)
      except Exception, e: print e
      self.tasks.task_done() #indicate the previous task has been processed
#Worker Class is ended here 

class ThreadPool:
  """Pool of threads consuming tasks from a queue"""
  def __init__(self, num_threads):
    self.tasks = Queue(num_threads)
    for _ in range(num_threads): Worker(self.tasks) #create a number of threads when initialize ThreadPool 

  def add_task(self, func, *args, **kargs):
    self.tasks.put((func, args, kargs)) #each task is a function pointer along with arguments
    
  def wait_completion(self):
    """Wait for completion of all the tasks in the queue"""
    self.tasks.join()
  
  def empty():
    return self.tasks.empty()   
#ThreadPool Class is ended here       
