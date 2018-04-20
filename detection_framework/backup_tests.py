#  This file contains all the detection test code

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


from interruptable_thread import InterruptableThread
from subprocess import call
from math import log
from socket import inet_ntoa
from Queue import Queue
from collections import deque
from entropy_test import *
from wavelet_test import *
from req_rsp import *
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

			#print "test"
                        # Add only newly added nfcapd files
                        if current_time < os.path.getmtime(abs_fname):
				# add the new nfcapd file to the queue
				abs_fname = abs_fname.replace(os.path.abspath(dirname),'')
				cmd[4] = abs_fname
				copy_dirname = 'nfdump'
				abs_csv_fname = os.path.abspath(os.path.join(copy_dirname, fname)) + '.csv'
				if os.path.isfile(abs_csv_fname) == False:
					self.file_lock.acquire()
					try:
						with open(abs_csv_fname, 'wb') as ff:
							call(cmd, stdout=ff)
					finally:
						self.file_lock.release()

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
    def read_nfcapd(self, current_time):
    	file_queue = deque()

    	#print threading.currentThread().getName(), 'Read nfcapd()'
    

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
			print self.completed_files[nfdump_file]
			print "by %s %d" % (name, self.completed_files[nfdump_file])
			# if the count is equal to the number of detection threads, file is no longer needed
			if self.completed_files[nfdump_file] == self.test_count and os.path.isfile(nfdump_file) == True:
				os.remove(nfdump_file)
				self.files_tested += 1
				print "file %d: %s tested, executed by %s" % (self.files_tested, nfdump_file, name)
    	finally:
			self.completed_files_lock.release()


    # Detection Threads
    # One thread for each type of detection test
    # Later add option to enable/disable certain tests
    def dns_ampl_test(self, t):
        current_time = 0

    	print threading.currentThread().getName(), 'Starting'
    	while not t.is_stop_requested():
    		entropy_tester = Entropy()
    	
    		time.sleep(2)
    		file_queue = deque()
    		time.sleep(2)
    		file_queue = deepcopy(self.read_nfcapd(current_time))
    		while len(file_queue) > 1:
             		#print("dns", nfdump_file)

             		# Run the test here on each file in the queue
			entropy_tester.feature = "da"
			entropy_tester.data_type = "netflow"
			entropy_tester.ent_type = "avg_size"

			filename = file_queue.popleft()

			print filename
			if filename in self.completed_files:
				if self.completed_files[filename] < self.test_count:
             		  		entropy_tester.detect_entropy_ts(filename)
					self.nfdump_complete(filename, "ent")
			else:
				entropy_tester.detect_entropy_ts(filename)
			#else: # tstat file
				#entropy_tester.detect_entropy_ts(filename)

	     		# update the completed_files dict to indicate the thread has completed processing this file
	     			self.nfdump_complete(filename, "ent")

			if entropy_tester.log_entry != "":
				logging.info(entropy_tester.log_entry)
	     

    		if len(file_queue) == 1:
             		current_time = file_queue.popleft()
    	#logging.info('finished entropy')

    def dns_rsp_test(self, t):
    	current_time = 0

    	print threading.currentThread().getName(), 'Starting'
    	while not t.is_stop_requested():
    		rsp_tester = RequestResponse()

    	
    		time.sleep(3)
    		file_queue = deque()
    		time.sleep(2)
    		file_queue = deepcopy(self.read_nfcapd(current_time))
    		while len(file_queue) > 1:
            		nfdump_file = file_queue.popleft()

			if nfdump_file in self.completed_files:
                                if self.completed_files[filename] < self.test_count:
            				# Insert dns response test code here
					rsp_tester.detect_reflection(nfdump_file)
	    				# remove the completed files 
	    				self.nfdump_complete(nfdump_file, "Rsp")
			else:
				rsp_tester.detect_reflection(nfdump_file)
				self.nfdump_complete(nfdump_file, "Rsp")

			if rsp_tester.log_entry != "":
                                logging.info(rsp_tester.log_entry)

    		if len(file_queue) == 1:
            		current_time = file_queue.popleft()
		#logging.info('wavelet')
    	#logging.info('done wavelet')

    def wavelet_test2(self, t):
    	current_time = 0
    
    	print threading.currentThread().getName(), 'Starting'
    	while not t.is_stop_requested():
    		wavelet_tester = Wavelet()
		time.sleep(1)
    		file_queue = deque()
    		file_queue = deepcopy(self.get_nfcapd(current_time))
    		while len(file_queue) > 1:
            		nfcapd_file = file_queue.popleft()

            		# Insert wavelet test code here
            		wavelet_tester.list_of_files.append(nfcapd_file)
			wavelet_tester.run_wavelet()
			if wavelet_tester.log_entry != "":
				logging.info(wavelet_tester.log_entry)

    		if len(file_queue) == 1:
            		current_time = file_queue.popleft()
		#logging.info('wavelet')
    	#logging.info('done wavelet')

    def tcp_syn_test(self, t):
    	print threading.currentThread().getName(), 'Starting'
    	time.sleep(4)
    	print threading.currentThread().getName(), 'Exiting'	

    def run_threads(self):
	self.test_count = 1
	t1 = InterruptableThread(self.dns_ampl_test)
    	t2 = InterruptableThread(self.wavelet_test2)
    	t1.start()
    	t2.start()
	t1.join()
    	t2.join()

