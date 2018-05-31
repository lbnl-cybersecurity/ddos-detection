#  This file contains the code for handling new detection test threads

import socket
import struct
import os.path
import time
import sys
import csv
import getopt
import collections
import shutil
import thread
import threading
import signal
import logging
import importlib
import globals

from expiringdict import *
from interruptable_thread import InterruptableThread
from subprocess import call
from math import log
from socket import inet_ntoa
from Queue import Queue
from collections import deque
from entropy_test import *
from wavelet_test import *
from dns_test import *
from netflow_classes import * 
from copy import deepcopy

FORMAT = '[%(levelname)s] (%(threadName)-10s) %(message)s'


class DetectionTester:
    def __init__(self):
	self.log_file = ""
	self.files_tested = 0
        self.nf_directory = ""
	self.file_lock = threading.Lock()
	self.completed_files_lock = threading.Lock()
	self.completed_files = dict()
	self.test_count = 0
	self.file_type = "nfdump"
	self.cache = ExpiringDict(max_len=100000, max_age_seconds=86400)

    def configure_log(self):
	# configure the log
	logging.basicConfig(level=logging.DEBUG,
                    format=FORMAT)
	self.logger = logging.getLogger()
	lhStdout = self.logger.handlers[0]  # stdout is the only handler initially

    	file_handler = logging.FileHandler(self.log_file)
    	file_handler.setFormatter(logging.Formatter(FORMAT))
    	logging.getLogger().addHandler(file_handler)
    	self.logger.removeHandler(lhStdout)

    # Sort the nfcapd file list by modification time 
    def compare_times(self, file1, file2):
    	if os.path.isfile(file1) and os.path.isfile(file2):  
    		if os.path.getmtime(file1) < os.path.getmtime(file2):
        		return -1
    		elif os.path.getmtime(file1) > os.path.getmtime(file2):
        		return 1
    	else:
        	return 0
    	return 0

    # Update a queue of nfdump files to be read by the detector
    def get_nfcapd(self, current_time):
    	file_queue = deque()

    	#print threading.currentThread().getName(), 'Read nfcapd()'
    

    	lock = threading.Lock()

    	file_count = 0
     
    	# Read from the nfcapd files in the chosen directory
    	sortedFiles = []
    	fileTimes = []
    	nfDumpFiles = []
	abs_dirname = ""

    	file_count = 0
    	# For each new nfcapd file, get nfdump, then read nfdump and run the test
    	#nf_directory = "."
    	for dirname, subdirList, fileList in os.walk(self.nf_directory): #, topdown=False):
                fileList = [k for k in fileList if 'nfcapd' in k and not 'csv' in k]
	
		for i in range(len(fileList)):
			fileList[i] = os.path.abspath(os.path.join(dirname, fileList[i]))
		fileList = sorted(fileList, cmp=self.compare_times)

		abs_dirname = os.path.abspath(dirname)
                for fname in fileList:
                        abs_fname = os.path.abspath(os.path.join(dirname, fname))

                        # Add only newly added nfcapd files
                        if current_time < os.path.getmtime(abs_fname):
				# add the new nfcapd file to the queue
				#name = abs_fname.replace(os.path.abspath(dirname),'')
				file_queue.append(abs_fname) 
                                current_time = os.path.getmtime(abs_fname)
    	file_queue.append(current_time)
    	return file_queue

    # Update a queue of nfdump files to be read by the detector
    def read_nfcapd(self, current_time):
    	file_queue = deque()
    	lock = threading.Lock()

    	file_count = 0
     
    	# Read from the nfcapd files in the chosen directory
    	sortedFiles = []
    	fileTimes = []
    	nfDumpFiles = []

    	file_count = 0
    	# For each new nfcapd file, get nfdump, then read nfdump and run the test
	if "nfdump_path" in globals.test_vars:
    		cmd = [globals.test_vars["nfdump_path"], '-o', 'csv', '-r', 0]
	else:
		cmd = ['nfdump', '-o', 'csv', '-r', 0]
    	#nf_directory = "."
    	for dirname, subdirList, fileList in os.walk(self.nf_directory): #, topdown=False):
                fileList = [k for k in fileList if 'nfcapd' in k and not 'csv' in k]
	
		for i in range(len(fileList)):
			fileList[i] = os.path.abspath(os.path.join(dirname, fileList[i]))
		fileList = sorted(fileList, cmp=self.compare_times)

                for fname in fileList:
                        abs_fname = os.path.abspath(os.path.join(dirname, fname))
                        cmd[4] = abs_fname

                        # Test only newly added nfcapd files
                        if current_time < os.path.getmtime(abs_fname):
                                #file_count += 1
                                # Create an nfdump file                       
                                copy_dirname = 'nfdump'
				#fname = str(file_count) + fname
                                abs_csv_fname = os.path.abspath(os.path.join(copy_dirname, fname)) + '.csv'

				# Use a lock to prevent two threads from writing
				# the same nfdump file
				
				#print abs_csv_fname
				if os.path.isfile(abs_csv_fname) == False:
					self.file_lock.acquire()
					try:
                                		with open(abs_csv_fname, 'wb') as ff: 
							call(cmd, stdout=ff)
					finally:
						self.file_lock.release()
	
				# add the new nfdump file to the queue
				file_queue.append(abs_csv_fname)
                                current_time = os.path.getmtime(abs_fname)
    	file_queue.append(current_time)
    	return file_queue

    # Update a queue of flowtools files to be read by the detector
    # currently set to read flow-print output, update this
    def read_ft(self, current_time):
	file_queue = deque()

	lock = threading.Lock()
	file_count = 0

	sortedFiles = []
	fileTimes = []
	tstatFiles = []

	file_queue.append(abs_csv_fname)
        current_time = os.path.getmtime(abs_fname)	


    # Update a queue of nfdump files to be read by the detector
    def read_nfcapd_alt(self, current_time):
    	file_queue = deque()


    	lock = threading.Lock()

    	file_count = 0
     
    	# Read from the nfcapd files in the chosen directory
    	sortedFiles = []
    	fileTimes = []
    	nfDumpFiles = []

    	file_count = 0
    	# For each new nfcapd file, get nfdump, then read nfdump and run the test
    	#cmd = ['../nfdump/bin/nfdump', '-o', 'csv', '-r', 0]

    	#nf_directory = "."
    	for dirname, subdirList, fileList in os.walk(self.nf_directory): #, topdown=False):
                fileList = [k for k in fileList] #if 'nfcapd' in k and not 'csv' in k]
	
		for i in range(len(fileList)):
			fileList[i] = os.path.abspath(os.path.join(dirname, fileList[i]))
		fileList = sorted(fileList, cmp=self.compare_times)

                for fname in fileList:
                        abs_fname = os.path.abspath(os.path.join(dirname, fname))
                    
                        # Test only newly added nfcapd files
                        if current_time < os.path.getmtime(abs_fname):
				# Create an nfdump file
				copy_dirname = 'nfdump'
				abs_csv_fname = os.path.abspath(os.path.join(copy_dirname, fname)) + '.csv'

				#if os.path.isfile(abs_csv_fname) == False:
					#self.file_lock.acquire()
					#try:
					#	with open(abs_csv_fname, 'wb') as ff:
					#		call(cmd, stdout=ff)
					#finally:
					#	self.file_lock.release()
				# add the new nfdump file to the queue
				file_queue.append(abs_fname)
                                current_time = os.path.getmtime(abs_fname)
    	file_queue.append(current_time)
    	return file_queue
   
	# delete the nfdump files once all detection threads have finished processing them  	
	# detection threads should indication the completion of a file by calling this function	
    def nfdump_complete(self, nfdump_file, name):
    	self.completed_files_lock.acquire()
    	try:
			self.completed_files[nfdump_file] = self.completed_files.get(nfdump_file, 0) + 1
			#print self.completed_files[nfdump_file]
			#print "by %s %d" % (name, self.completed_files[nfdump_file])
			# if the count is equal to the number of detection threads, file is no longer needed
			if self.completed_files[nfdump_file] == self.test_count and os.path.isfile(nfdump_file) == True:
				os.remove(nfdump_file)
				self.files_tested += 1
				#print "file %d: %s tested, executed by %s" % (self.files_tested, nfdump_file, name)
    	finally:
			self.completed_files_lock.release()


    # Detection Threads
    # One thread for each type of detection test
    # Later add option to enable/disable certain tests
	
	# Generic function for starting a new test thread.  Calls the run_test method for a given module.
    def start_test(self, t, test_name):
        current_time = 0

  	#print test_name
    	print"Starting", test_name

	function_string = test_name
	mod_name, func_name = function_string.rsplit('.',1)
	mod = importlib.import_module(mod_name)
	func = getattr(mod, func_name)
	tester = func()

    	while not t.is_stop_requested():
    		time.sleep(2)
    		file_queue = deque()
    		time.sleep(2)
    		file_queue = deepcopy(self.read_nfcapd(current_time))
    		while len(file_queue) > 1:
             		#print("dns", nfdump_file)

             		# Run the test here on each file in the queue

			filename = file_queue.popleft()

			#print filename
			if filename in self.completed_files:
				if self.completed_files[filename] < self.test_count:
					#tester = func() #reset tester
 					tester.run_test(filename)
					self.nfdump_complete(filename, test_name)
			else:
				#tester = func()
				tester.run_test(filename)
			# update the completed_files dict to indicate the thread has completed processing this file
	     			self.nfdump_complete(filename, test_name)

			if tester.log_entry != "":
				logging.info(tester.log_entry)
				#print tester.log_entry
    		if len(file_queue) == 1:
             		current_time = file_queue.popleft()

