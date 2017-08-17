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

def write2file():
    global results

    #if len(results) % grid != 0:
    #    return
    print "Write entropy results to file..."
    ff = open(outfile, 'ab')
    for line in results:
        linestr = ','.join([str(k) for k in line])
        ff.write(linestr+'\n')
    results = []



# Read nfcapd files
# For now, we will write an nfdump file, then read flows from there 
# if this is too expensive
# then we can try piping or reading directly from nfcapd.
# Keep track of the file creation time, skip file if it's <= last time
# This way we don't read old files, only newly added ones. 
def nfdumpCSV(rootDir, copyDir):
    cmd = ['nfdump', '-o', 'csv', '-r', 0]
    for dirname, subdirList, fileList in os.walk(rootDir, topdown=False):
        fileList = [k for k in fileList if not 'csv' in k]
        for fname in fileList:
            abs_fname = os.path.abspath(os.path.join(dirname, fname))
            #print abs_fname
            cmd[4] = abs_fname

            tmp = dirname.split('/')
            tmp[0] = copyDir
            copy_dirname = '/'.join(tmp)
            abs_csv_fname = os.path.abspath(os.path.join(copy_dirname, fname)) + '.csv'
            #print abs_csv_fname
            with open(abs_csv_fname, 'wb') as ff:
                call(cmd, stdout=ff)

def dump(count):
    global results
    global target_count
    global target_flows

    #print("dump called 1")
    #destCounter = collections.Counter() # data structure for tracking flow volume
    topDest = 0
    topIP = 'empty'
          
    row = [count]
    #print("calculating entropy for file %d",count)
    ### calculate current entropy
    for field in options:
                #print(field)
                hx = 0
                total = sum([curr_s_dict[field][k] for k in curr_s_dict[field]])
                #print(total)
                for element in curr_s_dict[field]:
                        #  update destinationCounter to get top destinations
                        nx = curr_s_dict[field][element]

                        # Find the destination with the largest volume
                        # Update this to include more than just the top target
                        # Important to check for other possible targets
                        if field in "da":
                                if nx > topDest:
                                        topDest = nx
                                        topIP = element

                        px = nx/float(total)
                        hx += -1*px*log(px, 2)
                N0 = log(len(curr_s_dict[field]), 2)
                #print(N0)
                
                if N0 != 0:
                        hx_norm = hx/float(N0)
                        # check thresholds here

                        #for element in curr_s_dict[field]:
                                #print(element)
                        if field in "da":
                                print(hx_norm)
                        if field in "da" and hx_norm < 0.25:
                                print(topIP,topDest)
                                print("Potential DDoS attack found")
                                #ff = open(outfile, 'ab')
                                print("Target is: ", topIP, " Volume", topDest)
                                print(" Entropy: ", hx)
                                print(" Potential DDoS attack found\n")
    
def dump2(count):
    global results
    
    row = [count]
    print("Recording blank file", count)
    ### calculate current entropy
    for field in options:
                row.append(-1)
    row.append(target_flows)
    row.append(target_count)
    results.append(row)
    write2file()


def count(field, element, num):
    if not field in curr_s_dict:
        curr_s_dict[field] = {}

    if not element in curr_s_dict[field]:
        curr_s_dict[field][element] = num
    else:
        curr_s_dict[field][element] += num


def entropy(row):
    global curr_s_dict
    global current_file, prev_file
    global target_count
    global target_flows
    global start_time
    global test_count

    #if row[1] in target: # if the target is the destination, update the total count 
    #   target_count += row[5]
    #    target_flows += 1

    for i, field in enumerate(options):
            #print "counting"
            #count(field, row[i], row[5])
            if not field in curr_s_dict:
                curr_s_dict[field] = {}

            if not row[i] in curr_s_dict[field]:
                curr_s_dict[field][row[i]] = row[5]
                #print(row[5],field)
            else:
                curr_s_dict[field][row[i]] += row[5]

# Sort the nfcapd file list by modification time 
def compare_times(file1, file2):
    if os.path.getmtime(file1) < os.path.getmtime(file2):
        return -1
    elif os.path.getmtime(file1) > os.path.getmtime(file2):
        return 1
    else:
        return 0

# DDoS detection using entropy
def detect_entropy(nfdump):
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
                        entropy(ent_data)
                count += 1
    # Calculate entropy score and check for potential DDoS targets
    dump(0)
    curr_s_dict = {}


def main(argv):
    global flow_count
    global start_time

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

            # For each new nfcapd file, get nfdump, then read nfdump and run the test
            cmd = ['nfdump', '-o', 'csv', '-r', 0]
            for dirname, subdirList, fileList in os.walk(nf_directory, topdown=False):
                fileList = [k for k in fileList if not 'csv' in k]
                fileList = sorted(fileList, cmp=compare_times)
                for fname in fileList:
                        abs_fname = os.path.abspath(os.path.join(dirname, fname))
                        #print abs_fname
                        cmd[4] = abs_fname

                        # Test only newly added nfcapd files
                        if current_time < os.path.getmtime(abs_fname):
                                print("last modified: %s" % time.ctime(os.path.getmtime(abs_fname)))
                                # Create an nfdump file                       
                                copy_dirname = 'nfdump'
                                abs_csv_fname = os.path.abspath(os.path.join(copy_dirname, fname)) + '.csv'
                                #print abs_csv_fname
                                with open(abs_csv_fname, 'wb') as ff:
                                        call(cmd, stdout=ff)

                                current_time = os.path.getmtime(abs_fname)

                                # Read the nfdump file, run detection test
                                detect_entropy(abs_csv_fname)


            
            sys.exit()
         
if __name__ == "__main__":
    main(sys.argv[1:])