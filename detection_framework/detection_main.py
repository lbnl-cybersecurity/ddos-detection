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
from subprocess import call
from math import log
from socket import inet_ntoa

from entropy_test import *
from netflow_classes import * 

SIZE_OF_HEADER = 24
SIZE_OF_RECORD = 48

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 2346))
flow_count = 0
start_time = 0
current_time = 0
test_count = 1

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

# Sort the nfcapd file list by modification time 
def compare_times(file1, file2):
    if os.path.getmtime(file1) < os.path.getmtime(file2):
        return -1
    elif os.path.getmtime(file1) > os.path.getmtime(file2):
        return 1
    else:
        return 0


def main(argv):
    global flow_count
    global start_time

    entropy_tester = Entropy()

    nf_directory = ''
    log_file = ''

    try:
        opts, args = getopt.getopt(argv,"hi:o:",["ifile=","ofile="])
    except getopt.GetoptError:
        print 'detect.py -i <netflow directory> -o <log name>'
        sys.exit(2)
    if len(sys.argv) == 1:
        print 'detect.py -i <netflow directory> -o <log name>'
    for opt, arg in opts:
        if opt == '-h':
                print 'detect.py -i <netflow directory> -o <log name>'
                sys.exit()
        elif opt in ("-i", "--directory"):
                nf_directory = arg
        elif opt in ("-o", "--log"):
                log_file = arg
    print 'Input file is ', nf_directory
    print 'Output file is ', log_file

    while True:
            global flow_count
            global start_time
            global current_time
            
            # Read from the nfcapd files in the chosen directory
            sortedFiles = []
            fileTimes = []

	    file_count = 0
            # For each new nfcapd file, get nfdump, then read nfdump and run the test
            cmd = ['nfdump', '-o', 'csv', '-r', 0]
            for dirname, subdirList, fileList in os.walk(nf_directory, topdown=False):
                fileList = [k for k in fileList if 'nfcapd' in k and not 'csv' in k]
                fileList = sorted(fileList, cmp=compare_times)
                for fname in fileList:
                        abs_fname = os.path.abspath(os.path.join(dirname, fname))
                        #print abs_fname
                        cmd[4] = abs_fname

                        # Test only newly added nfcapd files
                        if current_time < os.path.getmtime(abs_fname):
				file_count += 1
				print(file_count)
                                print("last modified: %s" % time.ctime(os.path.getmtime(abs_fname)))
                                # Create an nfdump file                       
                                copy_dirname = 'nfdump'
                                abs_csv_fname = os.path.abspath(os.path.join(copy_dirname, fname)) + '.csv'
                                #print abs_csv_fname
                                with open(abs_csv_fname, 'wb') as ff:
                                        call(cmd, stdout=ff)

                                current_time = os.path.getmtime(abs_fname)

                                # Read the nfdump file, run detection test
				print abs_csv_fname
				if ".csv" in abs_csv_fname:
                                	entropy_tester.detect_entropy(abs_csv_fname)


            
            sys.exit()
         
if __name__ == "__main__":
    main(sys.argv[1:])
