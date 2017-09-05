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
		self.log_entry = ""


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
		self.log_entry = ""
    		for field in self.options:
                	#print(field)
                	hx = 0
                	total = sum([self.curr_s_dict[field][k] for k in self.curr_s_dict[field]])
                	#print(total)
                	for element in self.curr_s_dict[field]:
                        	#  update destinationCounter to get top destinations
                        	nx = self.curr_s_dict[field][element]

				# Find the destination with the largest volume
				# Update this to include more than just the top target
				# Important to check for other possible targets
                        	if field in "da":
                                	if nx > topDest:
                                        	topDest = nx
                                       		topIP = element

                        	px = nx/float(total)
                        	hx += -1*px*log(px, 2)
                	N0 = log(len(self.curr_s_dict[field]), 2)
                	#print(N0)
                
                	if N0 != 0:
                        	hx_norm = hx/float(N0)
                        	# check thresholds here

                        	#for element in self.curr_s_dict[field]:
                                	#print(element)
				if field in "da":
                        		print(hx_norm)
                        	if field in "da" and hx_norm < 0.95: #0.25:
					self.log_entry = "%s, %s, low entropy: %s, potential DDoS attack" % (topIP, topDest, hx_norm)
                                	#print(topIP,topDest)
                                	#print("Potential DDoS attack found")
                                	#ff = open(outfile, 'ab')
                                	#print("Target is: ", topIP, " Volume", topDest)
                                	#print(" Entropy: ", hx)
                                	#print(" Potential DDoS attack found\n")
    
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
    		#if row[1] in target: # if the target is the destination, update the total count 
    		#	target_count += row[5]
    		#    target_flows += 1

    		for i, field in enumerate(self.options):
            		#print "counting"
            		#count(field, row[i], row[5])
            		if not field in self.curr_s_dict:
                		self.curr_s_dict[field] = {}

            		if not row[i] in self.curr_s_dict[field]:
               			self.curr_s_dict[field][row[i]] = row[5]
            		else:
                		self.curr_s_dict[field][row[i]] += row[5]

	# Perform the test on an nfdump file
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