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

NUM_TESTS = 2 


# Location of nfcapd files to be tested
nf_directory = "" 

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 2346))
flow_count = 0
start_time = 0
#current_time = 0
test_count = 1
nf_directory = '.'

# track the nfdump files so they can be deleted once all threads have processed them
completed_files = dict()
completed_files_lock = threading.Lock()
files_tested = 0

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


# Update a queue of nfdump files to be read by the detector
def read_nfcapd(current_time):
    global nf_directory

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
    for dirname, subdirList, fileList in os.walk(nf_directory): #, topdown=False):
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
					lock.acquire()
					try:
                                		with open(abs_csv_fname, 'wb') as ff:
							call(cmd, stdout=ff)
					finally:
						lock.release()
	
				# add the new nfdump file to the queue
				file_queue.append(abs_csv_fname)
                                current_time = os.path.getmtime(abs_fname)
    file_queue.append(current_time)
    return file_queue
   
# delete the nfdump files once all detection threads have finished processing them  	
# detection threads should indication the completion of a file by calling this function	
def nfdump_complete(nfdump_file):
    global files_tested
    global completed_files

    completed_files_lock.acquire()
    try:
			completed_files[nfdump_file] = completed_files.get(nfdump_file, 0) + 1
			# if the count is equal to the number of detection threads, file is no longer needed
			if completed_files[nfdump_file] >= NUM_TESTS:
				os.remove(nfdump_file)
				files_tested += 1
				print ("file %d tested" % files_tested)
    finally:
			completed_files_lock.release()


# Detection Threads
# One thread for each type of detection test
# Later add option to enable/disable certain tests
def dns_ampl_test(t):
    current_time = 0

    print threading.currentThread().getName(), 'Starting'
    while not t.is_stop_requested():
    	entropy_tester = Entropy()
    	
    	time.sleep(2)
    	file_queue = deque()
    	time.sleep(2)
    	file_queue = deepcopy(read_nfcapd(current_time))
    	while len(file_queue) > 1:
             nfdump_file = file_queue.popleft()
             #print("dns", nfdump_file)

             # Run the test here on each file in the queue
             entropy_tester.detect_entropy(nfdump_file)
	     logging.info(entropy_tester.log_entry)

	     # update the completed_files dict to indicate the thread has completed processing this file
	     nfdump_complete(nfdump_file)
	     

    	if len(file_queue) == 1:
             current_time = file_queue.popleft()
	if entropy_tester.log_entry != "":
		logging.info(entropy_tester.log_entry)
    logging.info('finished entropy')

def wavelet_test(t):
    current_time = 0
    
    print threading.currentThread().getName(), 'Starting'
    while not t.is_stop_requested():
    	#entropy_tester = Entropy()

    	
    	time.sleep(3)
    	file_queue = deque()
    	time.sleep(2)
    	file_queue = deepcopy(read_nfcapd(current_time))
    	while len(file_queue) > 1:
            nfdump_file = file_queue.popleft()

            # Insert wavelet test code here
            #entropy_tester.detect_entropy(nfdump_file)

	    # remove the completed files 
	    nfdump_complete(nfdump_file)


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

    # use /project/projectdirs/hpcsecure/ddos/lbl-mr2-anon/2016/01/31/ for testing
    global nf_directory
    log_file = ""

    try:
        opts, args = getopt.getopt(argv,"hi:o:",["ifile=","ofile="])
    except getopt.GetoptError:
        print 'detect.py -i <netflow directory> -o <log name>'
        sys.exit(2)
    if len(sys.argv) < 5:
        print 'detect.py -i <netflow directory> -o <log name>'
	sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
                print 'detect.py -i <netflow directory> -o <log name>'
                sys.exit()
        elif opt in ("-i", "--directory"):
                nf_directory = arg
        elif opt in ("-o", "--log"):
                log_file = arg
    print 'nfcapd directory is ', nf_directory
    print 'logfile name is ', log_file


    print ("starting threads")

    # set up the logging
    logging.basicConfig(level=logging.DEBUG,
                    format=FORMAT)

    logger = logging.getLogger() # this gets the root logger

    lhStdout = logger.handlers[0]  # stdout is the only handler initially
    #f = open(log_file,"w")          # example handler
    #lh = logging.StreamHandler(f)
    #logger.addHandler(lh)
    

    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(logging.Formatter(FORMAT))
    logging.getLogger().addHandler(file_handler)
    logger.removeHandler(lhStdout)

    # start the detection threads
    t1 = InterruptableThread(dns_ampl_test)
    t2 = InterruptableThread(wavelet_test)
    t1.start()
    t2.start()

    # keep checking the nfcapd directory for new files, convert to csv and add them to a shared queue for the detection tests
    


    t1.join()
    t2.join() 

 
if __name__ == "__main__":
    main(sys.argv[1:])
