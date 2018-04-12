import os
import sys
dir_module = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
dir_module = os.path.join(dir_module, 'common_module')
sys.path.insert(0, dir_module)

import re
from extract import extract_udp, extract_toi
from attack_signature import target_ip, target_sport, target_prot, attack_type
import time

# Get all files in the dataset
indir = '/home/chang/nsds/dataset/anomaly_based/ssdp/csv'
pattern = 'ft_\d\d.csv$'
files = []
for rootdir, subdirs, filenames in os.walk(indir):
    files += [os.path.join(rootdir,ff) for ff in filenames if re.match(pattern, ff)]
files = sorted(files)
#print files

time_start = time.time()
udp_file = 'target_udp_traffic.csv'
ssdp_file = 'target_{0}.csv'.format(attack_type)

# Extract UDP traffic to/from target ip
if not os.path.isfile(udp_file):
    data = extract_udp(files, target_prot, target_ip)
    # There are in total 339043 records to/from target ip
    outfile = udp_file
    with open(outfile, 'wb') as ff:
        for line in data:
            ff.write(line)

# Extract SSDP traffic to target ip
if not os.path.isfile(ssdp_file):
    data = extract_toi([udp_file], target_prot, target_sport, target_ip)
    outfile = ssdp_file
    with open(outfile, 'wb') as ff:
        for line in data:
            ff.write(line)

time_end= time.time()
print "Time elapsed: ", time_end - time_start

