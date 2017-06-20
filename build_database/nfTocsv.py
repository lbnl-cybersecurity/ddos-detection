#!/usr/bin/python
""" 
    Convert nfcapd dump files to csv files using nfdump
    Usage: ./nfTocsv.py input-dir output-csv-dir
    
"""
import os
import sys
import shutil
from subprocess import call

# copy directory tree with only folders
def ig_f(dir, files):
    return [f for f in files if not os.path.isdir(os.path.join(dir, f))]

def copyDirectory(src, dst, ignore_func):
    try:
        shutil.copytree(src, dst, ignore = ignore_func)
    except shutil.Error as e:
        print 'error: %s' % e
    except OSError as e:
        print 'error: %s' % e

# write csv files to copyDir
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

def main():
    rootDir = sys.argv[1]
    copyDir = sys.argv[2]
    copyDirectory(rootDir, copyDir, ig_f)
    nfdumpCSV(rootDir, copyDir)

if __name__ == "__main__":
    main() 
        
