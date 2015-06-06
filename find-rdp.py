#! /usr/bin/env python
# find_rdp
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

try:
    import pcap
except ImportError:
    print 'libpcap not installed.\ntry : apt-get remove python-pypcap && apt-get install python-libpcap\nOn Mac OS X download http://downloads.sourceforge.net/project/pylibpcap/pylibpcap/0.6.4/pylibpcap-0.6.4.tar.gz \ntar xvf pylibpcap-0.6.4.tar.gz && cd pylibpcap-0.6.4\n./setup.py install'
    exit()
import logging
import argparse
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from base64 import b64decode
from threading import Thread
import pyasn
import pygeoip

def ShowWelcome():
    Message = 'find rdp connections'
    print Message

parser = argparse.ArgumentParser(description=' ')
m_group=parser.add_mutually_exclusive_group()
m_group.add_argument('-f', type=str, dest="fname", default=None, help="Pcap file to parse")
m_group.add_argument('-d', type=str, dest="dir_path", default=None, help="Pcap directory to parse recursivly")
m_group.add_argument('-i', type=str, dest="interface", default=None, help="interface for live capture")
parser.add_argument('-t', action="store_true", dest="timestamp", help="Include a timestamp in all generated messages (useful for correlation)")
parser.add_argument('-v', action="store_true", dest="Verbose", help="More verbose.")

options = parser.parse_args()

if options.fname is None and options.dir_path is None and options.interface is None:
    print '\n\033[1m\033[31m -f or -d or -i mandatory option missing.\033[0m\n'
    parser.print_help()
    exit(-1)

try:
	asndb = pyasn.pyasn('ipasn.dat')
	gi = pygeoip.GeoIP('GeoIP.dat')
except:
	print "You need ipasn.dat (pygeoip) and GeoIP.dat (maxmind db) to start this program"
	print "file has to be in libpcap format - editcap -F libpcap test.pcapng test.pcap may help"
	#exit(1)

ShowWelcome()
Verbose = options.Verbose
fname = options.fname
dir_path = options.dir_path
interface = options.interface
timestamp = options.timestamp
start_time = time.time()

Filename = str(os.path.join(os.path.dirname(__file__),"findrdp-Session.log"))
l= logging.getLogger('RDP-Session')
l.addHandler(logging.FileHandler(Filename,'a'))

ipaddress = []

def PrintPacket(Filename,Message):
    if Verbose == True:
        return True
    if os.path.isfile(Filename) == True:
        with open(Filename,"r") as filestr:
            if re.search(re.escape(Message), filestr.read()):
                filestr.close()
                return False
            else:
                return True
    else:
        return True

def IsCookedPcap(version):
    Cooked = re.search('Linux \"cooked\"', version)
    TcpDump = re.search('Ethernet', version)
    Wifi = re.search('802.11', version)
    if Wifi:
        print 'Using 802.11 format\n'
        return 1
    if Cooked:
        print 'Using Linux Cooked format\n'
        return 2
    if TcpDump:
        print 'Using TCPDump format\n'
        return 3
    else:
        print 'Unknown format, trying TCPDump format\n'
        return 3

protocols={6:'tcp',
           17:'udp',
           1:'icmp',
           2:'igmp',
           3:'ggp',
           4:'ipcap',
           5:'ipstream',
           8:'egp',
           9:'igrp',
           29:'ipv6oipv4',
}

def luhn(n):
    r = [int(ch) for ch in str(n)][::-1]
    return (sum(r[0::2]) + sum(sum(divmod(d*2,10)) for d in r[1::2])) % 10 == 0


def Decode_Ip_Packet(s):
    d={}
    d['version']=(ord(s[0]) & 0xf0) >> 4
    d['header_len']=ord(s[0]) & 0x0f
    d['tos']=ord(s[1])
    d['total_len']=socket.ntohs(struct.unpack('H',s[2:4])[0])
    d['id']=socket.ntohs(struct.unpack('H',s[4:6])[0])
    d['flags']=(ord(s[6]) & 0xe0) >> 5
    d['fragment_offset']=socket.ntohs(struct.unpack('H',s[6:8])[0] & 0x1f)
    d['ttl']=ord(s[8])
    d['protocol']=ord(s[9])
    d['checksum']=socket.ntohs(struct.unpack('H',s[10:12])[0])
    d['source_address']=pcap.ntoa(struct.unpack('i',s[12:16])[0])
    d['destination_address']=pcap.ntoa(struct.unpack('i',s[16:20])[0])
    if d['header_len']>5:
        d['options']=s[20:4*(d['header_len']-5)]
    else:
        d['options']=None
    d['data']=s[4*d['header_len']:]
    return d

def Print_Packet_Details(decoded,SrcPort,DstPort):
    if timestamp:
        ts = '[%f] ' % time.time()
    else:
        ts = ''
    try:
        return '%sprotocol: %s %s:%s > %s:%s' % (ts, protocols[decoded['protocol']],decoded['source_address'],SrcPort,
                                           decoded['destination_address'], DstPort)
    except:
        return '%s%s:%s > %s:%s' % (ts,decoded['source_address'],SrcPort,
                                           decoded['destination_address'], DstPort)


def ParseDataRegex(decoded, SrcPort, DstPort):
   
    if DstPort == 3389 :
        Message = Print_Packet_Details(decoded,SrcPort,DstPort)
        l.warning(Message)
	if not decoded['source_address'] in ipaddress:
		ipaddress.append(decoded['source_address'])
    if SrcPort == 3389 :
        Message = Print_Packet_Details(decoded,SrcPort,DstPort)
        l.warning(Message)
        if not decoded['source_address'] in ipaddress:
		ipaddress.append(decoded['source_address'])
    

def Print_Packet_Cooked(pktlen, data, timestamp):
    if not data:
        return
    if data[14:16]=='\x08\x00':
        decoded=Decode_Ip_Packet(data[16:])
        SrcPort =  struct.unpack('>H',decoded['data'][0:2])[0]
        DstPort =  struct.unpack('>H',decoded['data'][2:4])[0]
        ParseDataRegex(decoded, SrcPort, DstPort)

def Print_Packet_800dot11(pktlen, data, timestamp):
    if not data:
        return
    if data[32:34]=='\x08\x00':
        decoded=Decode_Ip_Packet(data[34:])
        SrcPort =  struct.unpack('>H',decoded['data'][0:2])[0]
        DstPort =  struct.unpack('>H',decoded['data'][2:4])[0]
        ParseDataRegex(decoded, SrcPort, DstPort)

def Print_Packet_Tcpdump(pktlen, data, timestamp):
    if not data:
        return
    if data[12:14]=='\x08\x00':
        decoded= Decode_Ip_Packet(data[14:])
        if len(decoded['data']) >= 2:
            SrcPort= struct.unpack('>H',decoded['data'][0:2])[0]
        else:
            SrcPort = 0
        if len(decoded['data']) > 2:
            DstPort = struct.unpack('>H',decoded['data'][2:4])[0]
        else:
            DstPort = 0
        ParseDataRegex(decoded, SrcPort, DstPort)

def decode_file(fname,res):
    if interface != None:
        try:
            p = pcap.pcapObject()
            net, mask = pcap.lookupnet(interface)
            p.open_live(interface, 1600, 0, 100)
            Message = " live capture started, using:%s\nStarting timestamp (%s) corresponds to %s"%(interface, time.time(), time.strftime('%x %X'))
            print Message
            l.warning(Message)
            while 1:
                p.dispatch(1, Print_Packet_Tcpdump)
        except (KeyboardInterrupt, SystemExit):
            print '\n\nCRTL-C hit...\nCleaning up...'
            sys.exit()
    else:
        try:
            p = pcap.pcapObject()
            p.open_offline(fname)
            l.warning('\n\n started, using:%s file'%(fname))
            Version = IsCookedPcap(res)
            if Version == 1:
                thread = Thread(target = p.dispatch, args = (0, Print_Packet_Cooked))
                thread.daemon=True
                thread.start()
                try:
                    while thread.is_alive():
                        thread.join(timeout=1)
                except (KeyboardInterrupt, SystemExit):
                    print '\n\nCRTL-C hit..Cleaning up...'
                    threading.Event().set()
            if Version == 2:
                thread = Thread(target = p.dispatch, args = (0, Print_Packet_Cooked))
                thread.daemon=True
                thread.start()
                try:
                    while thread.is_alive():
                        thread.join(timeout=1)
                except (KeyboardInterrupt, SystemExit):
                    print '\n\nCRTL-C hit..Cleaning up...'
                    threading.Event().set()
            if Version == 3:

                thread = Thread(target = p.dispatch, args = (0, Print_Packet_Tcpdump))
                thread.daemon=True
                thread.start()
                try:
                    while thread.is_alive():
                        thread.join(timeout=1)
                except (KeyboardInterrupt, SystemExit):
                    print '\n\nCRTL-C hit..Cleaning up...'
                    threading.Event().set()

        except Exception:
            print 'Can\'t parse %s'%(fname)

def Run():
    try:
        if dir_path != None:
            for root, dirs, files in os.walk(dir_path, topdown=False):
                for capfile in files:
                    FilePath = os.path.join(root, capfile)
                    Start_Time = time.time()
                    print '\nParsing: %s'%(FilePath)
                    p = subprocess.Popen(["file", FilePath], stdout=subprocess.PIPE)
                    res, err = p.communicate()
                    decode_file(FilePath,res)
                    Seconds = time.time() - Start_Time
                    FileSize = 'File size %.3g Mo'%(os.stat(FilePath).st_size/(1024*1024.0))
                    if Seconds>60:
                        minutes = Seconds/60
                        Message = '\n%s parsed in: %.3g minutes (%s).\n'%(FilePath, minutes, FileSize)
                        print Message
                        l.warning(Message)
                    if Seconds<60:
                        Message = '\n%s parsed in: %.3g seconds (%s).\n'%(FilePath, Seconds, FileSize)
                        print Message
                        l.warning(Message)

        if fname != None:
            p = subprocess.Popen(["file", fname], stdout=subprocess.PIPE)
            res, err = p.communicate()
            decode_file(fname,res)
            Seconds = time.time() - start_time
            FileSize = 'File size %.3g Mo'%(os.stat(fname).st_size/(1024*1024.0))
            if Seconds>60:
                minutes = Seconds/60
                Message = '\n%s parsed in: %.3g minutes (%s).\n'%(fname, minutes, FileSize)
                print Message
                l.warning(Message)
            if Seconds<60:
                Message = '\n%s parsed in: %.3g seconds (%s).\n'%(fname, Seconds, FileSize)
                print Message
                l.warning(Message)

        if interface != None:
            decode_file(fname,'')

	l.warning("IP-Address")
	for ip in ipaddress:
		try:
			prefix = asndb.lookup(ip)[1]
			asn = asndb.lookup(ip)[0]
			country = gi.country_code_by_addr(ip)
		except:
			prefix = "na"
			asn = "na"
			country ="na"
		l.warning(ip+", "+prefix+", "+asn+", "+country+" ")

    except:
        raise
print "find-rdp - (c)2015 Bjoern Stelte - "
Run()

