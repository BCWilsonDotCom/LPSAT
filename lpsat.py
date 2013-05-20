#!/usr/bin/env python
# LPSAT, Lightweight Python Subnet Audit Tool
# Brandon Wilson
# 04/29/2013 
# Usage: ./lpsat.py <subnet>
# Example: ./lpsat.py 172.27.2
#

#Import required modules
import sys,time,types,getopt,os,socket,re,subprocess
#import paramiko
from dns import resolver,reversename,exception

class ReverseResolver(resolver.Resolver):
    def __init__(self,timeout=1):
        resolver.Resolver.__init__(self)
        self.lifetime=timeout
    def get_hostname(self,ip):
        try:
            rev_name = reversename.from_address(ip)
            result = self.query(rev_name,"PTR").__iter__().next().to_text()[:-1]
            return "%s: %s\n"%(ip,result)
        except resolver.NXDOMAIN: return "%s: NXDOMAIN\n"%(ip)
        except exception.Timeout: return "%s: TIMEOUT\n"%(ip)
        except: return "%s: UNSPECIFIED ERROR\n"%(ip)

def ip_to_num(ip):
    '''Takes an IP string and returns its decimal equivalent'''
    octects = ip.split(".")
    if len(octects) == 4:
        num = sum([int(octects[i])<<((3-i)*8) for i in range(0,4)])
        if num < 0 or num > 0xFFFFFFFF: return None
        else: return num
    else:
        return None

def num_to_ip(num):
    '''Takes an decimal representation of an IP and converts to a string'''
    if num < 0 or num > 0xFFFFFFFF: return None
    else: return ".".join([str((num>>((3-i)*8))&0xFF) for i in range(0,4)])

class SimpleLog:
    def __init__(self,open_file):
        self.f = open_file
    def write(self,data):
        self.f.write(data)

'''
class GetInfo(PTR):
  def __init__(self,timeout=1):
		GetInfo.__init__(self)

	def getinfo(PTR):
		getos(PTR)
		getserial(PTR)
		getmodel(PTR)
		getcpu(PTR)
		getmemory(PTR)
		getkernel(PTR)

	def getos(PTR):
		s.oscheck ('uname')
		PTR + "os" = s.oscheck

	def getmemory(PTR):
		if PTR + "SunOS":
			s.memorycheck ('prtdiag |grep "System Configuration"'| sed 's/,//g'| sed 's/System Configuration://g' |sed 's/^[ \t]*//;s/[ \t]*$//')
		if PTR + "Linux":
			s.memorycheck ('cat /proc/meminfo |grep MemTotal' |awk '{print $2}' |sed 's/^[ \t]*//;s/[ \t]*$//')
		PTR + "memory" = s.memorycheck

	def getserial(PTR):
		if PTR + "SunOS":
			s.serialcheck()
		if PTR + "Linux":
			s.serialcheck()
		PTR + "serial" = s.serialcheck

	def getmodel(PTR):

	def getcpu(PTR):

	def getkernel(PTR):

class WriteInfo(hostname, memory, serial, cpu, os, kernel):
	def __init__(self,timeout=1):
		WriteInfo.__init__(self)

	def writedb(hostname, memory, serial, cpu, os, kernel):

	def writexls(hostname, memory, serial, cpu, os, kernel):

	def writescreen(hostname, memory, serial, cpu, os, kernel):
'''

def pingtest(ip):
	ping_response = os.system("ping -c 1 -t 5 " + ip)
	print(ping_response)

def main():
	#Main loop
	for i in range(1, 254):
		
		#Concat our SUBNET and i, for our IP
		ip = str(SUBNET) + "." + str(i)

		#Try to get the IP's PTR Record
		hostname = r.get_hostname(ip)
		pingtest(ip)
		
		
		#Did we find anything?
		#if hostname=="NXDOMAIN":
			#If we're here, then we didn't.
			#But can we ping it?
			#if pingtest(ip):
				#We can ping it. Let's try an SSH test.
				#if sshtest(ip):
					#We can SSH to it. Let's get it's info.
					#getinfo(ip)
				#else:
					#If we're here, then we CAN ping, but NOT SSH. FLAG!!!
					#print(ip, + "FLAG!!!")
		#else:
			#for PTR in hostname:
				#getinfo(PTR)

opts_str = \
'\n\
	USAGE:\n\
	python lpsat.py [First three octects of subnet]\n\
	Example: lpsat.py 172.27.3\n\
'

#Code Start
if __name__ == "__main__":

	#Set defaults
	timeout,nthreads,f = 10,10,sys.stdout

	if len(sys.argv)==1:
	   print opts_str
	   sys.exit(0)

	#Initialize some vars that we'll need
	SUBNET = str(sys.argv[1])
	OUTPUTFILE = "/tmp/audit." + SUBNET
	SSHFLAGS = "-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes"

	#Create our resolver
	r = ReverseResolver(timeout)

	#Set our Nameservers
	#r.Nameservers = ['172.27.2.220']

	#Create our ssh client
	#ssh = paramiko.sshclient()
	#ssh.set_missing_host_key_policy(
    #paramiko.AutoAddPolicy())
	
	#Call into our main function
	main()
