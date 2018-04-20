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
import logging
from subprocess import call
from math import log

from socket import inet_ntoa

# Test for DDoS attacks by looking at the 
# entropy scores and large volume flows
class Entropy:
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
		self.total_pkts = 0
		self.total_flows = 0
		
		# Settings
		self.feature = "sp"
		self.data_type = "netflow"
		self.ent_type = "avg_size"

	# Record the log file
	def write2file(self):
    		#if len(self.results) % grid != 0:
    		#    return
    		print "Write entropy results to file..."
    		ff = open(outfile, 'ab')
    		for line in self.results:
        		linestr = ','.join([str(k) for k in line])
        		ff.write(linestr+'\n')
    		self.results = []


	# Calculate final results
	# Call periodically after gathering counts
	def dump(self, count):
    		#print("dump called 1")
    		#destCounter = collections.Counter() # data structure for tracking flow volume
    		topDest = 0
    		topIP = 'empty'
          
    		row = [count]
    		#print("calculating entropy for file %d",count)
    		### calculate current entropy
		ent_result = ""
		self.log_entry = ""
		ent_result += str(self.total_pkts)
		ent_result += ","
		ent_result += str(self.total_flows)
		ent_result += ","
    		for field in self.options:
                	#print(field)
                	hx = 0
			total = 0
			total2 = 0 
			if field in self.curr_s_dict:
                		total = sum([self.curr_s_dict[field][k] for k in self.curr_s_dict[field]])
                		for element in self.curr_s_dict[field]:
					total2 += self.curr_s_dict[field][element]	
				#print total2
			#print "total1 %d" % (total)
                	for element in self.curr_s_dict[field]:
                        	#  update destinationCounter to get top destinations
                        	nx = self.curr_s_dict[field][element]
				#print "nx %d" % (nx)
				# Find the destination with the largest volume
				# Update this to include more than just the top target
				# Important to check for other possible targets
                        	if field in "da": 
                                	if nx > topDest:
                                		topDest = nx
                                		topIP = element

                        	px = nx/float(total)
				if px != 0:
                        		hx += -1*px*log(px, 2)
				else:
					print field
					print "no"
                	N0 = log(len(self.curr_s_dict[field]), 2)
                	#print(N0)
                
                	if N0 != 0:
                        	hx_norm = hx/float(N0)
                        	# check thresholds here

                        	ent_result += str(hx_norm)
				if field in "dp":
					print ent_result
				else:
					ent_result += ","
					#if hx_norm == 1.0:
						#print self.curr_s_dict['da']
                        	if field in self.feature:
					if hx_norm <= self.threshold:
						self.log_entry = "%s, %s, low entropy: %s, potential DDoS attack" % (topIP, topDest, hx_norm)
                                	
	def dump2(self, count):
    		row = [count]
    		print("Recording blank file", count)
    		### calculate current entropy
    		for field in options:
                	row.append(-1)
    			row.append(target_flows)
    			row.append(target_count)
    			self.results.append(row)
    		write2file()


	def count(self, field, element, num):
    		if not field in self.curr_s_dict:
        		self.curr_s_dict[field] = {}

    		if not element in self.curr_s_dict[field]:
        		self.curr_s_dict[field][element] = num
    		else:
        		self.curr_s_dict[field][element] += num


	# Update the counts for the entropy calculation
	# Call this function for each new flow
	def entropy(self, row):
    		
    		for i, field in enumerate(self.options):
            		#count(field, row[i], row[5])
            		if not field in self.curr_s_dict:
                		self.curr_s_dict[field] = {}

            		if not row[i] in self.curr_s_dict[field]:
				if self.ent_type == "avg_size":
               				self.curr_s_dict[field][row[i]] = row[5]/row[6]
				else if self.ent_type == "pkt_size":
					self.curr_s_dict[field][row[i]] = row[5]
				else if self.ent_type == "pkt_count":
					self.curr_s_dict[field][row[i]] = row[6]
				#print self.curr_s_dict[field][row[i]]
            		else:
				if self.ent_type == "avg_size":
                			self.curr_s_dict[field][row[i]] += row[5]/row[6]
				else if self.ent_type == "pkt_size":
					self.curr_s_dict[field][row[i]] += row[5]
				else if self.ent_type == "pkt_count":
					self.curr_s_dict[field][row[i]] += row[6]

			if self.curr_s_dict[field][row[i]] == 0:
				self.curr_s_dict[field][row[i]] += 1

	# Perform the entropy test on an nfdump file
	def detect_entropy(self, nfdump):
    		count = 0
    		item_count = 0
    		# Read the nfdump file, flow-by-flow
    		with open(nfdump, 'rb') as csvfile:
        		nfreader = csv.reader(csvfile, delimiter=',', quotechar='|')
        		for row in nfreader:
                		if count >= 1 and len(row) > 11:
                        		#print ', '.join(row)
                        		ent_data = []
                        		ent_data.append(row[3]) # src ip
                        		ent_data.append(row[4]) # dst ip
                        		ent_data.append(row[5]) # src port
                        		ent_data.append(row[6]) # dst port
                        		ent_data.append(row[11]) # packet count
                        		ent_data.append(count) # count
                        		#print(ent_data)
                        		self.entropy(ent_data)
                		count += 1
    		# Calculate entropy score and check for potential DDoS targets
    		self.dump(0)
    		self.curr_s_dict = {}
			
	# Perform the test on a tstat file (use for testing dtn data)
	def detect_entropy_ts_alt(self, tstat):
    		count = 0
    		item_count = 0
    		# Read the tstat file, flow-by-flow
    		with open(tstat, 'rb') as csvfile:
        		nfreader = csv.reader(csvfile, delimiter=',', quotechar='|')
        		for row in nfreader:
				#print row
                		if count >= 1:
                        		#print ', '.join(row)
                        		ent_data = []
				
                        		ent_data.append(row[4]) # src ip
                        		ent_data.append(row[5]) # dst ip
                        		ent_data.append(row[6]) # src port
                        		ent_data.append(row[7]) # dst port
                        		ent_data.append(row[8]) # packet count
                        		ent_data.append(count) # count
                        		#print(ent_data)
                        		self.entropy(ent_data)
                		count += 1
    		# Calculate entropy score and check for potential DDoS targets
		if 'sa' in self.curr_s_dict:
			#print "ent count"
			#print self.curr_s_dict['sa']
    			self.dump(0)
    		self.curr_s_dict = {}		
			
		

        # Perform the entropy test on tstat data file
        def detect_entropy_ts(self, tstat):

    		count = 0
    		item_count = 0
    		# Read the tstat file, flow-by-flow
    		with open(tstat, 'rb') as csvfile:
        		nfreader = csv.reader(csvfile, delimiter=',', quotechar='|')
        		for row in nfreader:
				row2 = row[0].split()
                		if count >= 1:
                        		ent_data = []
                        		ent_data.append(row2[0]) # src ip
                        		ent_data.append(row2[1]) # dst ip
                        		ent_data.append(row2[3]) # src port
                        		ent_data.append(row2[4]) # dst port
                        		ent_data.append(row2[5]) # packet count
					#ent_data.append(row2[6])
					#pkts
                        		ent_data.append(int(row2[5])) # count (next try entropy using packet size?)
					ent_data.append(int(row2[6])) # 5 = octets/size, 6 = packet count
					if row2[1] == "35.7.72.0" or row2[0] == "35.7.72.0":
					
						self.entropy(ent_data)
						self.total_pkts += int(row2[6])
						self.total_flows += 1
                		count += 1
		#print "done"
		self.dump(0)
                self.curr_s_dict = {}
    			
        def detect_entropy_dtn(self, tstat):

                count = 0
                item_count = 0
                # Read the tstat file, flow-by-flow
                with open(tstat, 'rb') as csvfile:
                        nfreader = csv.reader(csvfile, delimiter=',', quotechar='|')
                        for row in nfreader:
                                row2 = row[0].split(":,")
                                src = row[1].split(":")
				dst = row[2].split(":")
				
                                if count >= 0:
                                        #print ', '.join(row)
                                        ent_data = []
                   
					#src[0] = src[0]+src[1]+dst[0]+dst[1]
					#print src[0]

                                        ent_data.append(src[0]) # src ip
                                        ent_data.append(src[1]) # dst ip
                                        ent_data.append(dst[0]) # src port
                                        ent_data.append(dst[1]) # dst port
                                        #ent_data.append(row[5]) # packet count
					ent_data.append(row[5])
                                        ent_data.append(int(row[3])+int(row[5])) # count
					ent_data.append(int(row[4])+int(row[6]))
                                        #print(ent_data)
					if ent_data[5] != 0 and ent_data[6] != 0:
                                        	self.entropy(ent_data)
					self.total_pkts  += int(row[4]) + int(row[6])
					self.total_flows += 1
                                count += 1
                #print "done dtn"
		self.dump(0)
                self.curr_s_dict = {}
