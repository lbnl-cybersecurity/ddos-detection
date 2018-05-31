# Testing script.
# This script copies a random file from this directory
# every X minutes into another directory.
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

def main(argv):
  source = ""
  destination = ""
  timer = 5*60
  start = time.time()

  try:
        opts, args = getopt.getopt(argv,"hi:o:t:",["ifile=","ofile=","timer="])
  except getopt.GetoptError:
        print 'random_copy.py -i <netflow directory> -o <destination_directory> -t <time>'
        sys.exit(2)
  if len(sys.argv) < 7:
        print 'random_copy.py -i <netflow directory> -o <destination directory> -t <time>'
	sys.exit(2)
  for opt, arg in opts:
        if opt == '-h':
                print 'random_copy.py -i <netflow directory> -o <destination directory> -t time'
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
  file_choice = random.choice(os.listdir(source))

  while True:
	file_choice = random.choice(os.listdir(source))
	random_name = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))
	random_name += ".nfcapd"
	abs_fname = os.path.abspath(os.path.join(source, file_choice))
	abs_dest = os.path.abspath(os.path.join(destination, random_name))
  	copyfile(abs_fname,abs_dest)
	time.sleep(timer - ((time.time() - start) % timer))

if __name__ == "__main__":
    main(sys.argv[1:])

