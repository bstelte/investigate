#!/usr/bin/python2

# pcap_com_graph.py
#
# build network graph from a list of domains
# 
# output pdf:    network graph
# 
# (c) 2015 Bjoern Stelte
#
# DISCLAIMER - USE AT YOUR OWN RISK.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

import networkx as nx
import matplotlib.pyplot as plt
import pickle
import socket
import dpkt
import sys
import binascii
import argparse
import time
import datetime
import os
import logging
import datetime
import pyasn
import pygeoip

parser = argparse.ArgumentParser(description=' ')
m_group=parser.add_mutually_exclusive_group()
m_group.add_argument('-f', type=str, dest="fname", default=None, help="Pcap file to parse")
m_group.add_argument('-d', type=str, dest="dir_path", default=None, help="Pcap directory to parse recursivly")
options = parser.parse_args()
start_time = time.time()
fname = options.fname
dir_path = options.dir_path


try:
	G = pickle.load( open( "investigate_graph.p", "rb" ) )
	
except:
	#print "No old Graph found!"
	G=nx.Graph()

if options.fname is None and options.dir_path is None :
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

def asndbs(ip, ts):
	try:
		prefix = asndb.lookup(ip)[1]
		if isinstance(prefix, basestring):
			if (prefix not in G.nodes()):
				G.add_node(prefix)
			if (not G.has_edge(ip, prefix)):			
				G.add_edge(ip, prefix, date=ts)
				unique = 1
			#print prefix
	
		asn = asndb.lookup(ip)[0]
		if isinstance(asn, int):
			if (asn not in G.nodes()):	
				G.add_node("AS"+str(asn), date=ts)
			if (not G.has_edge(prefix, "AS"+str(asn))):
				G.add_edge(prefix, "AS"+str(asn), date=ts)
				unique = 1
			#print asn
	except:
		print "AS problem with "+ip
		pass
	#try:
		#isp = gi.isp_by_addr(ip)
		#if isinstance(isp, basestring):
		#	if ("ISP "+isp.lower() not in G.nodes()):
		#		G.add_node("ISP "+isp.lower(), date=ts)
		#	if (not G.has_edge(ip, "ISP "+isp.lower())):
		#		G.add_edge(ip, "ISP "+isp.lower(), date=ts)
		#		unique = 1
			#print isp	
	country = gi.country_code_by_addr(ip)
	if isinstance(country, basestring):
		if (country.lower() not in G.nodes()):
			G.add_node(country.lower(), date=ts)
		if (not G.has_edge("AS"+str(asn), country.lower())):
			G.add_edge("AS"+str(asn), country.lower(), date=ts)
			unique = 1
			#print country			
	#except:
	#	print "GeoIP problem with "+ip
	#	pass

def analyse(filepath):
	f = open(filepath)
	pcapReader = dpkt.pcap.Reader(f)
	#try:
	for ts, data in pcapReader:
	    ether = dpkt.ethernet.Ethernet(data)
	    if ether.type != dpkt.ethernet.ETH_TYPE_IP: raise
	    ip = ether.data
	    dst = socket.inet_ntoa(ip.dst)
	    src = socket.inet_ntoa(ip.src)
	    if (dst not in G.nodes()):
		G.add_node(dst, date=str(datetime.datetime.utcfromtimestamp(ts)))
	    if (src not in G.nodes()):
		G.add_node(src, date=str(datetime.datetime.utcfromtimestamp(ts)))
	    if (not G.has_edge(src, dst)):
				G.add_edge(src, dst, date=str(datetime.datetime.utcfromtimestamp(ts)))
	    asndbs(src, str(datetime.datetime.utcfromtimestamp(ts)))
	    asndbs(dst, str(datetime.datetime.utcfromtimestamp(ts)))
	#except:
	#	pass
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

Run()


try:
	plt.figure(figsize=(16,16));
	pos=nx.graphviz_layout(G)
	plt.axis('off');

	nx.draw_networkx_edges(G,pos,width=0.3,alpha=0.3)
	nx.draw_networkx_nodes(G,pos,node_color='g',line_width=0.1,node_size=30,alpha=0.3)
	nx.draw_networkx_labels(G,pos,font_size=1)
	plt.savefig("pcap_com_graph.pdf")
	plt.show
except:
	pass


