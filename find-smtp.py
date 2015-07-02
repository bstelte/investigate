#! /usr/bin/env python
# find_smtp
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
import matplotlib.pyplot as plt
from matplotlib.dates import YearLocator, MonthLocator, DateFormatter
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
import datetime
from base64 import b64decode
from threading import Thread
import pyasn
import pygeoip
import re
import matplotlib.dates as mp
import pylab
import pickle

def ShowWelcome():
    Message = 'find smtp connections'
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

Filename = str(os.path.join(os.path.dirname(__file__),"findSMTP-Session.log"))
l= logging.getLogger('SMTP-Session')
l.addHandler(logging.FileHandler(Filename,'a'))

try:
	mail_try = pickle.load( open( "find-smtp-mail_try.p", "rb" ) )
	mail_success = pickle.load( open( "find-smtp-mail_success.p", "rb" ) )
	ipaddress_src = pickle.load( open( "find-smtp-ipaddress_src.p", "rb" ) )
	ipaddress_dst = pickle.load( open( "find-smtp-ipaddress_dst.p", "rb" ) )
except:
	mail_try = {}
	mail_success = {}
	ipaddress_src = []
	ipaddress_dst = []

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

def Print_Packet_Details(decoded,SrcPort,DstPort,ts2):
    if timestamp:
        ts = '[%f] ' % time.time()
    else:
        ts = ''
    #print decoded['data']
    if "RCPT TO:" in decoded['data']:
	try:
		mail_try[decoded['source_address'],int(mp.epoch2num(ts2))] += 1
	except:
		mail_try[decoded['source_address'],int(mp.epoch2num(ts2))] = 1  	
	try:
		match = re.search(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", decoded['data'])		
		return '%sprotocol: %s %s:%s > %s:%s  %s RCPT TO: %s' % (ts, protocols[decoded['protocol']],decoded['source_address'],SrcPort,decoded['destination_address'], DstPort, str(datetime.datetime.utcfromtimestamp(ts2)), match.group())
    	except:
		return '%s%s:%s > %s:%s  %s RCPT TO: %s' % (ts,decoded['source_address'],SrcPort,decoded['destination_address'], DstPort, str(datetime.datetime.utcfromtimestamp(ts2)), match.group())
    if "MAIL FROM:" in decoded['data']:
    	try:
		match = re.search(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", decoded['data'])
		return '%sprotocol: %s %s:%s > %s:%s  %s MAIL FROM: %s' % (ts, protocols[decoded['protocol']],decoded['source_address'],SrcPort,decoded['destination_address'], DstPort, str(datetime.datetime.utcfromtimestamp(ts2)), match.group())
    	except:
		return '%s%s:%s > %s:%s  %s MAIL FROM: %s' % (ts,decoded['source_address'],SrcPort,decoded['destination_address'], DstPort, str(datetime.datetime.utcfromtimestamp(ts2)), match.group())
    if "From: " in decoded['data']:
    	try:
		match = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", decoded['data'])
		return '%sprotocol: %s %s:%s > %s:%s  %s mail body from / to: %s - %s' % (ts, protocols[decoded['protocol']],decoded['source_address'],SrcPort,decoded['destination_address'], DstPort, str(datetime.datetime.utcfromtimestamp(ts2)), match[0], match[1])
    	except:
		return '%s%s:%s > %s:%s  %s mail body from / to: %s - %s' % (ts,decoded['source_address'],SrcPort,decoded['destination_address'], DstPort, str(datetime.datetime.utcfromtimestamp(ts2)), match[0], match[1])
    return " "

def ParseDataRegex(decoded, SrcPort, DstPort, timestamp):
   
#    if DstPort == 25 :
#        Message = Print_Packet_Details(decoded,SrcPort,DstPort, timestamp)
#        l.warning(Message)
#	if not decoded['source_address'] in ipaddress_src:
#		ipaddress_src.append(decoded['source_address'])
    if ((DstPort == 25) or (DstPort == 465) or (DstPort == 587)) :
        Message = Print_Packet_Details(decoded,SrcPort,DstPort, timestamp)
        if (len(Message) > 1):
		l.warning(Message)
        if not decoded['destination_address'] in ipaddress_dst:
		ipaddress_dst.append(decoded['destination_address'])
	if not decoded['source_address'] in ipaddress_src:
		ipaddress_src.append(decoded['source_address'])
    

def Print_Packet_Cooked(pktlen, data, timestamp):
    if not data:
        return
    if data[14:16]=='\x08\x00':
        decoded=Decode_Ip_Packet(data[16:])
        SrcPort =  struct.unpack('>H',decoded['data'][0:2])[0]
        DstPort =  struct.unpack('>H',decoded['data'][2:4])[0]
        ParseDataRegex(decoded, SrcPort, DstPort, timestamp)

def Print_Packet_800dot11(pktlen, data, timestamp):
    if not data:
        return
    if data[32:34]=='\x08\x00':
        decoded=Decode_Ip_Packet(data[34:])
        SrcPort =  struct.unpack('>H',decoded['data'][0:2])[0]
        DstPort =  struct.unpack('>H',decoded['data'][2:4])[0]
        ParseDataRegex(decoded, SrcPort, DstPort, timestamp)

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
        ParseDataRegex(decoded, SrcPort, DstPort, timestamp)

def decode_file(fname,res):
    if interface != None:
        try:
            p = pcap.pcapObject()
            net, mask = pcap.lookupnet(interface)
            p.open_live(interface, 1600, 0, 100)
            Message = " live capture started, using:%s\nStarting timestamp (%s) corresponds to %s"%(interface, time.time(), time.strftime('%x %X'))
            print Message
            #l.warning(Message)
            while 1:
                p.dispatch(1, Print_Packet_Tcpdump)
        except (KeyboardInterrupt, SystemExit):
            print '\n\nCRTL-C hit...\nCleaning up...'
            sys.exit()
    else:
        try:
            p = pcap.pcapObject()
            p.open_offline(fname)
            #l.warning('\n\n started, using:%s file'%(fname))
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
                        #l.warning(Message)
                    if Seconds<60:
                        Message = '\n%s parsed in: %.3g seconds (%s).\n'%(FilePath, Seconds, FileSize)
                        print Message
                        #l.warning(Message)

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
                #l.warning(Message)
            if Seconds<60:
                Message = '\n%s parsed in: %.3g seconds (%s).\n'%(fname, Seconds, FileSize)
                print Message
                #l.warning(Message)

        if interface != None:
            decode_file(fname,'')

	l.warning("DST IP-Address")
	for ip in ipaddress_src:
		if isinstance(ip, basestring):
			try:
				prefix = asndb.lookup(ip)[1]
				asn = asndb.lookup(ip)[0]
				country = gi.country_code_by_addr(ip)
			except:
				prefix = "na"
				asn = "na"
				country ="na"			
			l.warning(ip+", "+str(prefix)+", "+str(asn)+", "+str(country)+" ")
	
    except:
        raise

print "find-smtp - (c)2015 Bjoern Stelte - "
Run()

#pic
values = []
dates =  [q[1] for q in mail_try]
srcs = [q[0] for q in mail_try]
for s in mail_try:
	values.append(mail_try[s])	

for ip in ipaddress_src:
	print "... figure findSMTP_"+ip+".png "
	pic_values = []
	pic_dates = []
	gen = (i for i,x in enumerate(srcs) if x == ip)
	for i in gen: 
		#print i
		pic_values.append(values[i])
		pic_dates.append(dates[i])

	yearsFmt = DateFormatter('%d.%m.%Y')
	fig, ax = plt.subplots()
	ax.plot_date(pic_dates, pic_values, 'bo')	
	ax.xaxis.set_major_formatter(yearsFmt)
	ax.autoscale_view()
	ax.fmt_xdata = DateFormatter('%d.%m.%Y')
	ax.grid(True)
	ax.set_title('SMTP '+ip)
	ax.set_ylabel('connections')
	#plt.ylim((0,5))
	fig.tight_layout()
	fig.autofmt_xdate(rotation=45)
	#plt.show()
	pylab.savefig('findSMTP_'+ip+'.png', bbox_inches='tight')

pickle.dump( mail_try, open( "find-smtp-mail_try.p", "wb" ) )
pickle.dump( mail_success, open( "find-smtp-mail_success.p", "wb" ) )
pickle.dump( ipaddress_src, open( "find-smtp-ipaddress_src.p", "wb" ) )
pickle.dump( ipaddress_dst, open( "find-smtp-ipaddress_dst.p", "wb" ) )

