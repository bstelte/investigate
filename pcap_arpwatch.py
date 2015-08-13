#! /usr/bin/env python
# pcap_arpwatch
# (c)2015 Bjoern Stelte
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import socket
import dpkt
import sys
import binascii
import argparse
import time
import os
import logging
import datetime
import pyasn
import pygeoip

macaddress=[]
count={}

parser = argparse.ArgumentParser(description=' ')
m_group=parser.add_mutually_exclusive_group()
m_group.add_argument('-f', type=str, dest="fname", default=None, help="Pcap file to parse")
m_group.add_argument('-d', type=str, dest="dir_path", default=None, help="Pcap directory to parse recursivly")
options = parser.parse_args()
start_time = time.time()
fname = options.fname
dir_path = options.dir_path

Filename = str(os.path.join(os.path.dirname(__file__),"pcap_arpwatch.log"))
l= logging.getLogger('Session')
l.addHandler(logging.FileHandler(Filename,'a'))

if options.fname is None and options.dir_path is None :
    print '\n\033[1m\033[31m -f or -d mandatory option missing.\033[0m\n'
    parser.print_help()
    exit(-1)

try:
	asndb = pyasn.pyasn('ipasn.dat')
	gi = pygeoip.GeoIP('GeoIP.dat')
except:
	print "You need ipasn.dat (pygeoip) and GeoIP.dat (maxmind db) to start this program"
	print "file has to be in libpcap format - editcap -F libpcap test.pcapng test.pcap may help"
	#exit(1)

def add_colons_to_mac( mac_addr ) :
    s = list()
    for i in range(12/2) : 	
        s.append( mac_addr[i*2:i*2+2] )
    r = ":".join(s)		
    return r

def analyse(filepath):
	f = open(filepath)
	pcapReader = dpkt.pcap.Reader(f)
	try:
		for ts, data in pcapReader:
		    ether = dpkt.ethernet.Ethernet(data)
		    if ether.type != dpkt.ethernet.ETH_TYPE_IP: raise
		    ip = ether.data
		    dst = socket.inet_ntoa(ip.dst)
		    dstmax = add_colons_to_mac(binascii.hexlify(ether.dst))
		    #print "%s -> %s" % (dst,dstmax)
		    add=dst+", "+dstmax
		    if not add in macaddress:
			macaddress.append(add)
			try:
				prefix = asndb.lookup(ip)[1]
				asn = asndb.lookup(ip)[0]
				country = gi.country_code_by_addr(ip)
			except:
				prefix = "na"
				asn = "na"
				country ="na"
			l.warning(add+", "+filepath+", "+str(datetime.datetime.utcfromtimestamp(ts))+", "+prefix+", "+asn+", "+country+" ")
		    if not dst in count:
			count[dst]=0
		    count[dst]+=1
	except:
		pass
	#	print "file has to be in libpcap format - editcap -F libpcap test.pcapng test.pcap may help"

def Run():
    try:
        if dir_path != None:
            for root, dirs, files in os.walk(dir_path, topdown=False):
                for capfile in files:
                    FilePath = os.path.join(root, capfile)
                    Start_Time = time.time()
                    print '\nParsing: %s'%(FilePath)
                    analyse(FilePath)
                    Seconds = time.time() - Start_Time
                    FileSize = 'File size %.3g Mo'%(os.stat(FilePath).st_size/(1024*1024.0))
                    if Seconds>60:
                        minutes = Seconds/60
                        Message = '\n%s parsed in: %.3g minutes (%s).\n'%(FilePath, minutes, FileSize)
                        print Message
                        
                    if Seconds<60:
                        Message = '\n%s parsed in: %.3g seconds (%s).\n'%(FilePath, Seconds, FileSize)
                        print Message
                        

        if fname != None:
            analyse(fname)
            Seconds = time.time() - start_time
            FileSize = 'File size %.3g Mo'%(os.stat(fname).st_size/(1024*1024.0))
            if Seconds>60:
                minutes = Seconds/60
                Message = '\n%s parsed in: %.3g minutes (%s).\n'%(fname, minutes, FileSize)
                print Message
                
            if Seconds<60:
                Message = '\n%s parsed in: %.3g seconds (%s).\n'%(fname, Seconds, FileSize)
                print Message
               

    except:
        raise
print "pcap_arpwatch - (c)2015 Bjoern Stelte - "
Run()

for address in macaddress:
	print address

print

for c,v in count.items():
	print "ip: "+str(c)+"    packets: "+str(v)
