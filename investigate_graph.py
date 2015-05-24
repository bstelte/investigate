#!/usr/bin/python2

# investigate_graph.py
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

try:
	G = pickle.load( open( "investigate_graph.p", "rb" ) )
	
except:
	#print "No old Graph found!"
	G=nx.Graph()
try:
	plt.figure(figsize=(16,16));
	pos=nx.graphviz_layout(G)
	plt.axis('off');

	nx.draw_networkx_edges(G,pos,width=0.3,alpha=0.3)
	nx.draw_networkx_nodes(G,pos,node_color='g',line_width=0.1,node_size=30,alpha=0.3)
	nx.draw_networkx_labels(G,pos,font_size=1)
	plt.savefig("investigate.pdf")
	plt.show
except:
	pass


