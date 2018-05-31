# Request-based DDoS detection methods
# Use these methods on nfdump data
# Test for unusually large requests from a given port number

import socket
import struct
import os.path
import time
import sys
import csv
import getopt
import collections
import shutil
import math
import logging
import globals

from subprocess import call
from math import log
from expiringdict import *
from socket import inet_ntoa

# Test for DDoS attacks by looking at  
# abnormally high requests and responses
class RequestResponse:
	def __init__(self):
        	self.curr_s_dict = {}
		self.curr_tr_epoch = 0
		self.options = ['sa', 'da', 'sp', 'dp']
		self.outfile = 'ddosLog.txt'
		self.result = []
		self.grid = 500
		self.target_count = 0
		self.target_flows = 0
		self.target = "204.38.0.0/21"
		self.flow_count = 0
		self.no_dump = False
		self.log_entry = ""
		self.results1 = []
		self.results2 = []
		self.results3 = []
		self.results4 = []
		self.results5 = []
		self.results6 = []
		self.results7 = []
		self.results8 = []
		self.results9 = []
		self.max_pkts = 0 # highest packet count per 5 minutes
		self.max_flow = "" # flow with highest pkts
		self.max_pkts_req = 0
		self.max_flow_req = ""
		if "request_cache_time" in globals.test_vars:
			seconds = globals.test_vars["request_cache_time"]
		else:
			seconds = 86400
		self.cache = ExpiringDict(max_len=10000000, max_age_seconds=seconds)
		self.repeating = 1	

		# Settings
		self.protocol_port = 53
		self.pkt_thresh = 1000000
		self.size_thresh = 900
		  			
        def detect_reflection(self, tstat):

		# dictionary - key is request srcIP 
		# 	       value is a list of flow data arrays
		aggregate_reqs = {}
		aggregate_rsps = {}

		target = "207.75.112.0" #radb
		#target = "204.38.0.0" #dns_ampl
                count = 0
                item_count = 0
                # Read the tstat file, flow-by-flow
                with open(tstat, 'rb') as csvfile:
                        nfreader = csv.reader(csvfile, delimiter=',', quotechar='|')
                        for row in nfreader:
                                row2 = row[0].split()
                                #print row2
                                if count >= 1 and len(row) > 11:
					# 53 is for dns protocol
					# 19 is for chargen
					ent_data = []
                     			ent_data.append(row[3]) # src ip
                     			ent_data.append(row[4]) # dst ip
                     			ent_data.append(row[5]) # src port
                     			ent_data.append(row[6]) # dst port
                     			ent_data.append(row[12]) # octets
                     			ent_data.append(row[11]) # packet count
                     			ent_data.append(row[7]) # protocol - 17 is UDP

					if row[6] == self.protocol_port:									
						aggregate_reqs.setdefault(row[3], []).append(ent_data)
					if row[5] == self.protocol_port:
						aggregate_rsps.setdefault(row[4],[]).append(ent_data)	
						
                        	count += 1

			#  Check request total
			for key in aggregate_reqs:
				agg_pkts = 0
				agg_size = 0
				for flow_list in aggregate_reqs[key]:
					if flow_list[5].isdigit() and flow_list[4].isdigit():
						agg_pkts += int(flow_list[5])
						agg_size += int(flow_list[4])
				if self.max_pkts_req < agg_pkts:
                                        self.max_pkts_req = agg_pkts
                                        self.max_flow_req = key
	
				self.log_entry = ""
				if agg_pkts > self.pkt_thresh:

					if key not in self.cache:
                        		# possible attack,raise alert
						self.log_entry = "High requests sent to %s, %d response packets with port %s" % (key, agg_pkts,self.protocol_port)
						if self.repeating == 0:
							self.cache[key] = 1
					

	# Run the dns request test
	def run_test(self, nfdump):
		if "request_thresh" in globals.test_vars:
			self.pkt_thresh = int(globals.test_vars["request_thresh"])
		if "request_port" in globals.test_vars:
			self.protocol_port = globals.test_vars["request_port"]
		if "request_repeat" in globals.test_vars:
			self.repeating = int(globals.test_vars["request_repeat"])
		self.detect_reflection(nfdump)				
