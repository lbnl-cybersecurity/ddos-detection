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
from wavelet_test import *
from detection_tests import *
from netflow_classes import * 
from copy import deepcopy

def main(argv):
    # use /project/projectdirs/hpcsecure/ddos/lbl-mr2-anon/2016/01/31/ for testing

    detection_tester = DetectionTester()

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
                detection_tester.nf_directory = arg
        elif opt in ("-o", "--log"):
                detection_tester.log_file = arg
    print 'nfcapd directory is ', detection_tester.nf_directory
    print 'logfile name is ', detection_tester.log_file


    print ("starting threads")
    # start the detection threads
    detection_tester.configure_log()
    #detection_tester.run_threads()
    detection_tester.test_count = 2 # number of nfdump-based tests, for removing the finished files
    t1 = InterruptableThread(detection_tester.dns_ampl_test)
    t2 = InterruptableThread(detection_tester.dns_rsp_test)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

 
if __name__ == "__main__":
    main(sys.argv[1:])
