# Entropy and volume based DDoS detection methods
# Use these methods on flow data in detection_framework.py
# Performs the test and creates the log file

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
from subprocess import call
from math import log

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

		# Settings
		self.protocol = "dns"
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
                                if count >= 0:
					# 53 is for dns protocol
					# 19 is for chargen

					ent_data = []
                                        #print row2[0]
                                        #print row2[1]
                                        #print row2[3]
                                        #print row2[4]
                                        #print row2[6]
                                        #print "end"
                                        ent_data.append(row2[0]) # src ip
                                        ent_data.append(row2[1]) # dst ip
                                        ent_data.append(row2[3]) # src port
                                        ent_data.append(row2[4]) # dst port
                                        #ent_data.append(row[5]) # packet count
                                        ent_data.append(row2[5]) # octets
                                        ent_data.append(row2[6]) # packet count
                                        ent_data.append(row2[2]) # protocol - 17 is UDP


					if row2[4] == "53":# and row2[2] == "17":									
						aggregate_reqs.setdefault(row2[0], []).append(ent_data)
					if row2[3] == "53":# and row2[2] == "17":
						aggregate_rsps.setdefault(row2[1],[]).append(ent_data)	
					#print row2[0]
					#if len(aggregate_reqs[row2[0]]) > 1:
					#print aggregate_reqs							
                        	count += 1

			#  Check request total
			for key in aggregate_reqs:
				agg_pkts = 0
				agg_size = 0
				for flow_list in aggregate_reqs[key]:
					if flow_list[5].isdigit() and flow_list[4].isdigit():
						agg_pkts += int(flow_list[5])
						agg_size += int(flow_list[4])
				if agg_pkts > 1:
					self.results1.append(str(agg_pkts))
					self.results2.append(str(agg_size)) 
			
				if self.max_pkts_req < agg_pkts:
                                        self.max_pkts_req = agg_pkts
                                        self.max_flow_req = key
	
				elif agg_pkts > self.pkt_thresh:
					# check the record more closely
					# calculate standard deviation of request size
					std_dev = 0
					mean = agg_size/len(aggregate_reqs[key])
					square_sum = 0
					square = 0
					for flow_list in aggregate_reqs[key]:
						if flow_list[5].isdigit() and flow_list[4].isdigit():
							square_sum += abs(int(flow_list[4]) - mean)*abs(int(flow_list[4]) - mean)
				
					square = square_sum/len(aggregate_reqs[key])
					std_dev = math.sqrt(square)
					
				
					if len(aggregate_reqs[key]) > agg_pkts/2 and square != 0:
						if std_dev < 1:
							print ""
					else:
						for flow_list in aggregate_reqs[key]:
							if flow_list[2] not in "53":
								# possible attack, raise alert
								break
		# Part 2 of detection test - Check responses
		for key in aggregate_rsps:
				agg_pkts = 0
                                agg_size = 0
                                for flow_list in aggregate_rsps[key]:
                                        if flow_list[5].isdigit() and flow_list[4].isdigit():
                                                agg_pkts += int(flow_list[5])
                                                agg_size += int(flow_list[4])

				self.results3.append(str(agg_pkts))
				self.results4.append(str(agg_size))
				
				if self.max_pkts < agg_pkts:
					self.max_pkts = agg_pkts 
					self.max_flow = key

				if target in key:
                                        self.results6.append("attack")
                                else:
                                        self.results6.append("not attack")
				self.results9.append(key)
				#print "working DNS"
                                if agg_pkts > self.pkt_thresh:
                                        # possible attack,raise alert
					self.log_entry = "High DNS responses sent to %s, %d response packets" % (key, agg_pkts)
					print self.log_entry

                                #elif agg_pkts > self.pkt_thresh/10:
				#	if agg_size/len(aggregate_rsps[key]) > size_thresh:
					# possible attack, raise alert
					#self.log_entry = "Potential attack"					
