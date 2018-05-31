# Testing script.
# This script copies nfcapd files from a given directory
# every X minutes into another directory.
# The files are copied in order based on modification date to simulate incoming traffic.
# Use this script for testing the detection tool
# which monitors newly recorded nfcapd files.

import os
import random
import string
import sys
import getopt
import os.path
import time
from shutil import copyfile

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

def main(argv):
  source = ""
  destination = ""
  timer = 5*60
  start = time.time()

  try:
        opts, args = getopt.getopt(argv,"hi:o:t:",["ifile=","ofile=","timer="])
  except getopt.GetoptError:
        print 'ordered_copy.py -i <netflow directory> -o <destination_directory> -t <time>'
        sys.exit(2)
  if len(sys.argv) < 7:
        print 'ordered_copy.py -i <netflow directory> -o <destination directory> -t <time>'
	sys.exit(2)
  for opt, arg in opts:
        if opt == '-h':
                print 'ordered_copy.py -i <netflow directory> -o <destination directory> -t time'
                sys.exit()
        elif opt in ("-i", "--input"):
                source = arg
        elif opt in ("-o", "--output"):
                destination = arg
	elif opt in ("-t", "--time"):
		timer = int(arg)
  print 'nfcapd directory is ', source
  print 'destination directory is ', destination
  print 'repeat copy every %d seconds' % (timer)

  # Read from the nfcapd files in the chosen directory
  fileList = []

  for dirname, subdirList, fileList in os.walk(source): #, topdown=False):
  	fileList = [k for k in fileList if 'nfcapd' in k and not 'csv' in k]
	
	for i in range(len(fileList)):
		fileList[i] = os.path.abspath(os.path.join(dirname, fileList[i]))
	fileList = sorted(fileList, cmp=compare_times)

   # copy the files in order, with a pause between copying
  for file in fileList:
	#abs_fname = os.path.abspath(os.path.join(source, file_choice))
	start_filename = file.rfind('/') + 1
	second_name = file[start_filename:]

	abs_dest = os.path.abspath(os.path.join(destination, second_name))
  	copyfile(file,abs_dest)
	#print abs_dest
	time.sleep(timer - ((time.time() - start) % timer))

if __name__ == "__main__":
    main(sys.argv[1:])

