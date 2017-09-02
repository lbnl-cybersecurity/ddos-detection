# Basic DDoS detection system for Netflow data
# Read from a directory of nfcapd files
# Continously checks this directory for new files, runs test and returns results
# Later, add options for reading other file types (ft-tools format)

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

# contains new nfdump files to be read
#file_queue = Queue()

global stop_threads



SIZE_OF_HEADER = 24
SIZE_OF_RECORD = 48

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 2346))
flow_count = 0
start_time = 0
#current_time = 0
test_count = 1
nf_directory = '.'


# Detection variables
bin_size = 5*60                   # seconds
pattern = '%Y-%m-%d %H:%M:%S'   # date_time format

# outer dict{ key: attribute; value: inner dict}
# inner dict{ key: distinct element; value: frequency}
curr_s_dict = {}
# time reference to divide into unit time slots
curr_tr_epoch = 0
# attributes for which to plot timeseries entropy 
options=['sa', 'da', 'sp', 'dp']

# file to save entropy results per unit time
outfile = 'ddosLog.txt'
results = []    # hold entropy values
grid = 500
target_count = 0 # how many packets sent to the target
target_flows = 0 # how many flows include the target destination

target = "204.38.0.0/21"

FORMAT = '[%(levelname)s] (%(threadName)-10s) %(message)s'


# Sort the nfcapd file list by modification time 
def compare_times(file1, file2):
    if os.path.isfile(file1) and os.path.isfile(file2):  
    	if os.path.getmtime(file1) < os.path.getmtime(file2):
        	return -1
    	elif os.path.getmtime(file1) > os.path.getmtime(file2):
        	return 1
    	else:
        	return 0
    return 0

# Return a list of unread nfdump files, in order
def find_new_files():
# Read from a queue made by other function instead
            global start_time
            global current_time
	   

            # Read from the nfcapd files in the chosen directory
            sortedFiles = []
            fileTimes = []
	    nfDumpFiles = []


	    dump_directory = nf_directory + "/nfdump"
	    #print dump_directory
            file_count = 0
            # Add each new nf_dump file to a list for testing
            for dirname, subdirList, fileList in os.walk(dump_directory, topdown=False):
                fileList = [k for k in fileList if 'nfcapd' in k and 'csv' in k]
                fileList = sorted(fileList, cmp=compare_times)
                for fname in fileList:
                        abs_fname = os.path.abspath(os.path.join(dirname,fname)) 
			#print fname	

                        # Test only newly added nfcapd files
                        if current_time < os.path.getmtime(abs_fname):
				print fname[0]
				nfDumpFiles.append(abs_fname)
                                current_time = os.path.getmtime(abs_fname)
	    return nfDumpFiles


# Update a queue of nfdump files to be read by the detector
def read_nfcapd(current_time):
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
    cmd = ['nfdump', '-o', 'csv', '-r', 0]
    nf_directory = "."
    for dirname, subdirList, fileList in os.walk("."): #, topdown=False):
		#print "reached files"
                fileList = [k for k in fileList if 'nfcapd' in k and not 'csv' in k]
		#print fileList
                fileList = sorted(fileList, cmp=compare_times)
                for fname in fileList:
                        abs_fname = os.path.abspath(os.path.join(dirname, fname))
                        cmd[4] = abs_fname

			#print "test"
                        # Test only newly added nfcapd files
                        if current_time < os.path.getmtime(abs_fname):
                                #file_count += 1
                                #print(file_count)
                                #print("last modified: %s" % time.ctime(os.path.getmtime(abs_fname)))
                                # Create an nfdump file                       
                                copy_dirname = 'nfdump'
				#fname = str(file_count) + fname
                                abs_csv_fname = os.path.abspath(os.path.join(copy_dirname, fname)) + '.csv'
                                
				# Use a lock to prevent two threads from writing
				# the same nfdump file
				
				if os.path.isfile(abs_csv_fname) == False:
					lock.acquire()
					try:
						print abs_csv_fname
                                		with open(abs_csv_fname, 'wb') as ff:
                                        		call(cmd, stdout=ff)
					finally:
						lock.release()
	
				# add the new nfdump file to the queue
				file_queue.append(abs_csv_fname)
				#print "reached"
                                current_time = os.path.getmtime(abs_fname)
    file_queue.append(current_time)
    return file_queue
     		
# Detection Threads
# One thread for each type of detection test
# Later add option to enable/disable certain tests
def dns_ampl_test(t):
    while not t.is_stop_requested():
    	entropy_tester = Entropy()
    	current_time = 0
    	print threading.currentThread().getName(), 'Starting'
    	time.sleep(2)
    	file_queue = deque()
    	time.sleep(2)
    	file_queue = deepcopy(read_nfcapd(current_time))
    	while len(file_queue) > 1:
             nfdump_file = file_queue.popleft()
             print("dns", nfdump_file)

             # Run the test here on each file in the queue
             entropy_tester.detect_entropy(nfdump_file)

    	if len(file_queue) == 1:
             current_time = file_queue.popleft()
	logging.info('entropy')
    logging.info('finished entropy')

def wavelet_test(t):
    while not t.is_stop_requested():
    	#entropy_tester = Entropy()
    	current_time = 0
    	print threading.currentThread().getName(), 'Starting'
    	time.sleep(3)
    	file_queue = deque()
    	time.sleep(2)
    	file_queue = deepcopy(read_nfcapd(current_time))
    	while len(file_queue) > 1:
            nfdump_file = file_queue.popleft()
            print("wavelet", nfdump_file)

            # Insert wavelet test code here
            #entropy_tester.detect_entropy(nfdump_file)


    	if len(file_queue) == 1:
            current_time = file_queue.popleft()
	logging.info('wavelet')
    logging.info('done wavelet')


def tcp_syn_test():
    print threading.currentThread().getName(), 'Starting'
    time.sleep(4)
    print threading.currentThread().getName(), 'Exiting'

# Call a detection test
def detection_test(name, nfdump_file):
        print "running"
        print name
        print "on"
        print nfdump_file	

def main(argv):
    print ("starting threads")

    # set up the logging
    logging.basicConfig(level=logging.DEBUG,
                    format=FORMAT)

    logger = logging.getLogger() # this gets the root logger

    lhStdout = logger.handlers[0]  # stdout is the only handler initially
    #f = open("results.log","w")          # example handler
    #lh = logging.StreamHandler(f)
    #logger.addHandler(lh)
    

    file_handler = logging.FileHandler('results.log')
    file_handler.setFormatter(logging.Formatter(FORMAT))
    logging.getLogger().addHandler(file_handler)
    logger.removeHandler(lhStdout)

    # start the threads!
    t1 = InterruptableThread(dns_ampl_test)
    t2 = InterruptableThread(wavelet_test)
    t1.start()
    t2.start()
    t1.join()
    t2.join() 

 
if __name__ == "__main__":
    main(sys.argv[1:])
