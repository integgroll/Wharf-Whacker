#!/usr/bin/env python
import socket
import SocketServer
import signal
import sys
import hashlib
from time import strftime, gmtime, sleep
from Queue import Queue
from threading import Thread

class WharfWhacker:
  def __init__(self,ip_address,password,safe_ports,authentication_length):
    self.ip_address = ip_address
    self.password = password
    self.safe_ports = safe_ports
    self.authentication_length = authentication_length 
    self.start_port = 0
    self.reserved_pool = ThreadPool(self.authentication_length*10+1)
    self.connection_sockets = []
    self.connections = dict()
    self.banlist = dict()
    self.keepgoing = True
    self.reserved_pool.add_task(self.new_ports)

    while True:    
      pass
      
    
  def new_ports(self):
    # This section is developing which ports to use. <- Pro commenting skills bro, no srsly
    while self.keepgoing:
      self.start_port = 0
      self.connections = dict()
      #Generates the new start port
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
      if temp_port > 1024 and temp_port not in self.safe_ports:
        self.start_port = temp_port
      x = x + 5

  def check_ports(self,ipaddress,port): 
    # Logic hell that deals with the ports, and where they are at in the authentication sequence
    if ipaddress in self.connections:
      print self.connections[ipaddress]
      if self.connections[ipaddress][self.connections[ipaddress][0]] == port:
        #Correct port hit
        self.connections[ipaddress][0] = self.connections[ipaddress][0] + 1
        if self.connections[ipaddress][0] >= self.authentication_length + 1:
          #Fully Authenticated
          self.allow_ip(ipaddress)
          del self.connections[ipaddress]
      else:
        #Incorrect port hit
        del self.connections[ipaddress]
        print "Connection Reset" + ipaddress
    else:
      if self.start_port==port:
        #Correct start port, creates sockets for other ports
        print "Session started, Creating secure ports"
        self.connections[ipaddress] = [1]
        self.generate_secure_ports(ipaddress)
        print "Secure Ports Created"
      else:
        if port not in self.safe_ports:
          #totally wrong, nuke the hell out of it with the ban list
          print "Failcamp - banlisting"
          del self.connections[ipaddress]
          if ipdaddress in self.banlist:
            self.banlist[ipaddress] = self.banlist[ipaddress] + 1
          else:
            self.banlist[ipaddress] = 1

  def generate_secure_ports(self,ipaddress):
    # This is the function that you need to change to generate a list of ports to knock against
    porthash = hashlib.sha512(ipaddress + self.password+strftime("%Y - %j - %d - %H - %M",gmtime())).hexdigest()  
    x = 0
    while len(self.connections[ipaddress]) < self.authentication_length + 1 :
      temp_port = int(porthash[x:x+4],16)
      if temp_port > 1024:
        self.connections[ipaddress].append(temp_port)    
      x = x + 5
    for port in self.connections[ipaddress]:
      self.reserved_pool.add_task(self.stream_reader,port)
      
  def stream_reader(self,port):
    # Creates a WharfServer to listen on a specific port
    self.connection_sockets.append(WharfServer((self.ip_address,port),InitialUDPHandler,self))
    self.connection_sockets[-1].serve_forever()

  def allow_ip(self,ipaddress):
    # Where the IPTables code will go
    print ipaddress + "confirmed!"
    
  def teardown(self):
    self.keepgoing = False
#WharfWhacker Class is ended here    


class Whacker():
  def __init__(self,ip_address,password,safe_ports,authentication_length):
    self.password = password
    self.authentication_length = authentication_length
    self.safe_ports = safe_ports
    self.ports = []
    self.ip_address = ip_address
    self.generate_ports()
    
  def whack(self,target_ip):
    # Runs a knock against target server
    first = True
    for i in self.ports:
      print i
      s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      s.sendto("are those pants?",(target_ip,i))
      if first:
        #We have to sleep here because most servers can't run the hashes for the ip's
        #AND open new sockets in the time before the next packet shows up.
        sleep(1)
        first = False
    
  def generate_ports(self):
    # Generates the ports that the knock will use.
    #Initial port to knock on
    porthash = hashlib.sha512(self.password+strftime("%Y - %j - %d - %H - %M",gmtime())).hexdigest()
    x = 0
    while len(self.ports) < 1 :
      temp_port = int(porthash[x:x+4],16)
      if temp_port > 1024:
        self.ports.append(temp_port)
      x = x + 5
    #Ports that are based on the IP
    porthash = hashlib.sha512(self.ip_address + self.password+strftime("%Y - %j - %d - %H - %M",gmtime())).hexdigest()  
    x=0
    while len(self.ports) < self.authentication_length + 1 :
      temp_port = int(porthash[x:x+4],16)
      if temp_port > 1024:
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