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
    	cmd = ['../nfdump/bin/nfdump', '-o', 'csv', '-r', 0]

    	#nf_directory = "."
    	for dirname, subdirList, fileList in os.walk(self.nf_directory): #, topdown=False):
                fileList = [k for k in fileList if 'nfcapd' in k and not 'csv' in k]
	
		for i in range(len(fileList)):
			fileList[i] = os.path.abspath(os.path.join(dirname, fileList[i]))
		fileList = sorted(fileList, cmp=self.compare_times)

                for fname in fileList:
                        abs_fname = os.path.abspath(os.path.join(dirname, fname))
                        cmd[4] = abs_fname

			#print "test"
                        # Test only newly added nfcapd files
                        if current_time < os.path.getmtime(abs_fname):
                                #file_count += 1
                                # Create an nfdump file                       
                                copy_dirname = 'nfdump'
				#fname = str(file_count) + fname
                                abs_csv_fname = os.path.abspath(os.path.join(copy_dirname, fname)) + '.csv'
                                
				# Use a lock to prevent two threads from writing
				# the same nfdump file
				
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
   
	# delete the nfdump files once all detection threads have finished processing them  	
	# detection threads should indication the completion of a file by calling this function	
    def nfdump_complete(self, nfdump_file, name):
    	self.completed_files_lock.acquire()
    	try:
			self.completed_files[nfdump_file] = self.completed_files.get(nfdump_file, 0) + 1
			
			print "by %s %d" % (name, self.completed_files[nfdump_file])
			# if the count is equal to the number of detection threads, file is no longer needed
			if self.completed_files[nfdump_file] >= self.test_count and os.path.isfile(nfdump_file) == True:
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
             		nfdump_file = file_queue.popleft()
             		#print("dns", nfdump_file)

             		# Run the test here on each file in the queue
             		entropy_tester.detect_entropy(nfdump_file)

	     		# update the completed_files dict to indicate the thread has completed processing this file
	     		self.nfdump_complete(nfdump_file, "ent")

			if entropy_tester.log_entry != "":
				logging.info(entropy_tester.log_entry)
	     

    		if len(file_queue) == 1:
             		current_time = file_queue.popleft()
    	#logging.info('finished entropy')

    def wavelet_test(self, t):
    	current_time = 0
    
    	print threading.currentThread().getName(), 'Starting'
    	while not t.is_stop_requested():
    		#entropy_tester = Entropy()

    	
    		time.sleep(3)
    		file_queue = deque()
    		time.sleep(2)
    		file_queue = deepcopy(self.read_nfcapd(current_time))
    		while len(file_queue) > 1:
            		nfdump_file = file_queue.popleft()

            		# Insert wavelet test code here
            		#entropy_tester.detect_entropy(nfdump_file)

	    		# remove the completed files 
	    		self.nfdump_complete(nfdump_file, "Wav")


    		if len(file_queue) == 1:
            		current_time = file_queue.popleft()
		#logging.info('wavelet')
    	#logging.info('done wavelet')


    def tcp_syn_test(self, t):
    	print threading.currentThread().getName(), 'Starting'
    	time.sleep(4)
    	print threading.currentThread().getName(), 'Exiting'	

    def run_threads(self):
	self.test_count = 2
	t1 = InterruptableThread(self.dns_ampl_test)
    	t2 = InterruptableThread(self.wavelet_test)
    	t1.start()
    	t2.start()
	t1.join()
    	t2.join()

