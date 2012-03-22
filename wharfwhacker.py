#!/usr/bin/env python
import socket
import select
import sys
import subprocess
import hashlib
import hmac
import os
import random
from time import strftime, gmtime, sleep

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
    self.white_list = attributes['white_list'].split(",")
    self.black_list = attributes['black_list'].split(",")
    self.whack_threshhold = int(attributes['whack_threshhold'])
    self.ignore_ports = self.secured_ports + self.safe_ports
    self.authentication_length = int(attributes['knocks'])
    if attributes['auth_token_key'] != "":
      self.auth_token_key = attributes['auth_token_key'].decode("hex")
    self.connection_sockets = []
    self.check_these_ports = []
    self.start_port = 0
    self.connections = dict()
    self.ban_list = dict()

  def start(self):
    #iptables set for WharfWhacker, the readme explains this.
    subprocess.call("iptables -N WharfWhacker" , shell = True)
    subprocess.call("iptables -N WharfWhacked" , shell = True)
    self.add_iptable_rule("INPUT -p udp -j WharfWhacked")
    self.add_iptable_rule("WharfWhacker -p tcp -j REJECT")
    self.add_iptable_rule("WharfWhacked -p udp -j ACCEPT")
    for i in self.secured_ports:
      self.add_iptable_rule("INPUT -p tcp --destination-port " + str(i) + " -j WharfWhacker")
    #Take care of the white and black lists
    for i in self.white_list:
      self.add_iptable_rule("WharfWhacker -p tcp --source " + i.strip() + " -j ACCEPT")      
    for i in self.black_list:
      self.add_iptable_rule("WharfWhacked -p udp --source " + i.strip() + " -j REJECT")
      
    while True:
      if (int(strftime("%S"))) <= 5 or self.start_port == 0:
        self.new_ports()
      #Code that actually operates things
      responses, blank, exceptions = select.select(self.connection_sockets,[],self.connection_sockets,5)
      for response in responses:
        if response in self.connection_sockets:
          connection , addr = response.recvfrom(100)
          self.check_ports(addr[0],response.getsockname()[1])
          responses.append(connection)
            
  def check_ports(self,ip_address,port): 
    # Checking Ports
    # Logic hell that deals with the ports, and where they are at in the authentication sequence
    if ip_address in self.connections:
      if self.connections[ip_address][self.connections[ip_address][0]] == port:
        # Correct port hit
        self.connections[ip_address][0] = self.connections[ip_address][0] + 1
        if self.connections[ip_address][0] >= self.authentication_length + 1:
          #Fully Authenticated
          self.allow_ip(ip_address)
          del self.connections[ip_address]
      else:
        #Incorrect port hit
        self.ban_check(ip_address)
        del self.connections[ip_address]
    else:
      if self.start_port==port:
        #Correct start port, creates sockets for other ports
        self.connections[ip_address] = [1]
        self.generate_secure_ports(ip_address)
      else:
        if port not in self.safe_ports:
          #totally wrong, nuke the hell out of it with the ban list
          #Failcamp - banlisting
          self.ban_ip(ip_address)
          del self.connections[ip_address]
          self.ban_check(ip_address)
    
  def new_ports(self):
    # This section is developing which ports to use. <- Pro commenting skills bro, no srsly
    self.start_port = 0
    self.connections = dict()
    self.check_these_ports = []
    #Culls the start socket, and the other sockets created over the past minute due to connection attempts
    for sock in self.connection_sockets:
      sock.close()
    self.connection_sockets = []
    #Generates the new start port and opens it up for reading
    self.generate_initial_port()
    
  def generate_initial_port(self):
    # Uses the porthash that was generated
    porthash = hmac.new(self.password,strftime("%Y - %m - %d - %H - %M",gmtime())+self.auth_token_value(),hashlib.sha512).hexdigest()
    x=0
    while self.start_port == 0 :
      temp_port = int(porthash[(x%512):((x+4)%512)],16)
      if temp_port > 1024 and temp_port not in self.ignore_ports:
        self.start_port = temp_port
      x = x + 5
    self.use_port(self.start_port)

  def generate_secure_ports(self,ip_address):
    # This is the function that you need to change to generate a list of ports to knock against
    porthash = hmac.new(self.password,ip_address + strftime("%Y - %m - %d - %H - %M",gmtime())+self.auth_token_value(),hashlib.sha512).hexdigest()
    x = 0
    while len(self.connections[ip_address]) < self.authentication_length + 1 :
      temp_port = int(porthash[x:x+4],16)
      if temp_port > 1024 and temp_port not in self.ignore_ports:
        self.connections[ip_address].append(temp_port)    
      x = x + 5
    for port in self.connections[ip_address]:
      self.use_port(port)
        
  def use_port(self,port):
    if port not in self.check_these_ports:
      temp = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
      temp.bind((self.ip_address,port))
      self.connection_sockets.append(temp)
      self.check_these_ports.append(port)
        
  def allow_ip(self,ip_address):
    # Where the IPTables code will go
    self.add_iptable_rule("WharfWhacker -p tcp --source " + ip_address + " -j ACCEPT")
    #print("Allowing IP: " + ip_address, file=sys.stderr)
    print >> sys.stderr, "Allowing IP: " + ip_address
    
  def ban_ip(self,ip_address):
    # Bans an IP
    self.add_iptable_rule("WharfWhacked -p udp --source " + ip_address + " -j REJECT")
    #print("Banning IP: " + ip_address, file=sys.stderr)
    print >> sys.stderr, "Banning IP: " + ip_address
        
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
      
  def auth_token_value(self):
    if self.auth_token_key:
      return hmac.new(self.auth_token_key,strftime("%Y - %m - %d - %H - %M",gmtime()),hashlib.sha256).hexdigest()[0:8]
    else:
      return ""
    
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
    
  def whack(self,target_ip,auth_key=""):
    self.generate_ports(auth_key)
    # Runs a knock against target server
    for i in self.ports:
      confusion = ""
      for j in range(0,random.randint(10,300)):
        confusion += chr(random.randint(0,255))      
      s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      s.sendto("are those pants?",(target_ip,i))
      #We have to sleep here because most servers can't run the hashes for the ip's
      #AND open new sockets in the time before the next packet shows up.
      sleep(0.01)
    print "Knock Complete, check for entry"
    
  def generate_ports(self,auth_key=""):
    # Generates the ports that the knock will use.
    #Initial port to knock on
    porthash = hmac.new(self.password,strftime("%Y - %m - %d - %H - %M",gmtime())+auth_key,hashlib.sha512).hexdigest()
    x = 0
    while len(self.ports) < 1 :
      temp_port = int(porthash[x:x+4],16)
      if temp_port > 1024 and temp_port not in self.ignore_ports:
        self.ports.append(temp_port)
      x = x + 5
    #Ports that are based on the IP
    porthash = hmac.new(self.password,self.ip_address + strftime("%Y - %m - %d - %H - %M",gmtime())+auth_key,hashlib.sha512).hexdigest()
    x=0
    while len(self.ports) < self.authentication_length + 1 :
      temp_port = int(porthash[x:x+4],16)
      if temp_port > 1024 and temp_port not in self.ignore_ports:
        self.ports.append(temp_port)
      x = x + 5    
#Whacker Class is ended here