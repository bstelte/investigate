#!/usr/bin/python2

# investigate.py
#
# build network graph from a list of domains
# input:         input.txt
# output stdout: csv list (only changes, remove pickle file to get actual list)
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

import whois
import pyasn
import socket
from dns import reversename, resolver
import networkx as nx
import matplotlib.pyplot as plt
import pygeoip
import datetime
import pickle

now = str(datetime.datetime.now())

#domains = ['set121.com','set133.com','adawareblock.com','mail.ya-support.com','changepassword-yahoo.com']
domains = [line.strip() for line in open("input.txt", 'r')]
#print domains

try:
	G = pickle.load( open( "investigate_graph.p", "rb" ) )
	
except:
	#print "No old Graph found!"
	G=nx.Graph()

#G=nx.random_geometric_graph(200,0.125)
#G=nx.cubical_graph()

try:
	asndb = pyasn.pyasn('ipasn.dat')
	gi = pygeoip.GeoIP('GeoIPOrg.dat')
except:
	print "You need ipasn.dat (pygeoip) and GeoIPISP.dat (maxmind db) to start this program"

def investigate(domain, G, asndb, gi):
	#print domain
	unique = 0
	ip = "127.0.0.1"

	if (domain not in G.nodes()):
		G.add_node(domain, date=now)
	
	try:
		w = whois.whois(domain)
		#print w.name_servers
		#print w.name
		#print w.emails
		
		if isinstance(w.name_servers, list):
			for values in w.name_servers:
				if (values not in G.nodes()):
					G.add_node(values.lower(), date=now)
				if (not G.has_edge(domain, values.lower())):
					G.add_edge(domain, values.lower(), date=now)
					unique = 1
		else:
			w.name_servers=[]
		
		if isinstance(w.name, basestring):
			if (w.name not in G.nodes()):
				G.add_node(w.name.lower(), date=now)
			if (not G.has_edge(domain, w.name.lower())):
				G.add_edge(domain, w.name.lower(), date=now)
				unique = 1
		else:
			w.name = " "
		
		if isinstance(w.emails, list):
			for values in w.emails:
				if ("abuse" not in values): 
					value = values
					if (value not in G.nodes()):
						G.add_node(value.lower(), date=now)
					if (not G.has_edge(domain, value.lower())):					
						G.add_edge(domain, value.lower(), date=now)
						unique = 1
		else:
			w.emails=[]
				
		ip = socket.gethostbyname(domain)

	except:
		unique = 0
		pass
	try:
		if isinstance(ip, basestring):
			if (ip not in G.nodes()):
				G.add_node(ip, date=now)
			if (not G.has_edge(domain, ip)):
				G.add_edge(domain, ip, date=now)
				unique = 1
			#print ip
		
		prefix = asndb.lookup(ip)[1]
		if isinstance(prefix, basestring):
			if (prefix not in G.nodes()):
				G.add_node(prefix)
			if (not G.has_edge(ip, prefix)):			
				G.add_edge(ip, prefix, date=now)
				unique = 1
			#print prefix
		
		asn = asndb.lookup(ip)[0]
		if isinstance(asn, int):
			if (asn not in G.nodes()):	
				G.add_node("AS"+str(asn), date=now)
			if (not G.has_edge(prefix, "AS"+str(asn))):
				G.add_edge(prefix, "AS"+str(asn), date=now)
				unique = 1
			#print asn
		
		#for prefixs in asndb.get_as_prefixes(asn):
		#	if (prefixs not in G.nodes()):
		#		G.add_node(prefixs, date=now)
		#	G.add_edge("AS"+str(asn), prefixs)
		#	print prefixs

	except:
		unique = 0
		pass
		
	#try:
	#	org = gi.org_by_addr(ip)
	#	if isinstance(org, basestring):
	#		if (org.lower() not in G.nodes()):
	#			G.add_node(org.lower(), date=now)
	#		G.add_edge(ip, org.lower(), date=now)
	#		#print org
	#
	#except:
	#	unique = 0
	#	pass
	
	try:
		isp = gi.isp_by_addr(ip)
		if isinstance(isp, basestring):
			if ("ISP "+isp.lower() not in G.nodes()):
				G.add_node("ISP "+isp.lower(), date=now)
			if (not G.has_edge(ip, "ISP "+isp.lower())):
				G.add_edge(ip, "ISP "+isp.lower(), date=now)
				unique = 1
			#print isp
			
	except:
		unique = 0
		pass
	try:
		if (unique > 0):
			print "'"+domain+"';'"+ip+"';'"+prefix+"';'"+w.name+"';'"+','.join(w.name_servers)+"';'"+','.join(w.emails)+"';'"+now+"'"
	
		rev_name = reversename.from_address(ip)
		rdns = str(resolver.query(rev_name,"PTR")[0])
		if isinstance(rdns, basestring):
			if (rdns not in G.nodes()):
				G.add_node(rdns, date=now)
			if (not G.has_edge(domain, rdns)):			
				G.add_edge(domain, rdns, date=now)
			#investigate(rdns, G, asndb)
	except:
		pass

print "'domain';'ip';'prefix';'whois.name';'whois.name_servers';'whois.emails';'datetime'"	

for domain in domains:
	if isinstance(domain, basestring):
		investigate(domain.lower(), G, asndb, gi)

pickle.dump( G, open( "investigate_graph.p", "wb" ) )

#print(G.nodes())
#print(G.edges())

#pos=nx.fruchterman_reingold_layout(G)
#pos=nx.get_node_attributes(G,'pos')
plt.figure(figsize=(16,16));
pos=nx.graphviz_layout(G)
plt.axis('off');
#nx.draw_networkx(G,pos,node_size=10,font_size=3)
nx.draw_networkx_edges(G,pos,width=0.3,alpha=0.3)
nx.draw_networkx_nodes(G,pos,node_color='g',line_width=0.1,node_size=30,alpha=0.3)
nx.draw_networkx_labels(G,pos,font_size=1)
plt.savefig("investigate.pdf")
plt.show


