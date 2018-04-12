import sys
import os
dir_module = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
dir_module = os.path.join(dir_module, 'common_module')
sys.path.insert(0, dir_module)

from extract import extract_udp, extract_toi
from attack_signature import target_ip, target_prot, target_sport, attack_type

infile = 'victim_dns_2015.csv'
files = [infile]

import time
time_start = time.time()
udp_file = 'target_udp_traffic.csv'
if not os.path.isfile(udp_file):
    # Extract UDP traffic to/from target ip
    data = extract_udp(files, target_prot, target_ip)
    outfile = udp_file
    with open(outfile, 'wb') as ff:
        for line in data:
            ff.write(line)

dns_file = 'target_dns.csv'
if not os.path.isfile(dns_file):
    # Extract DNS traffic to target ip
    data = extract_toi([udp_file], target_prot, target_sport, target_ip)
    outfile = dns_file
    with open(outfile, 'wb') as ff:
        for line in data:
            ff.write(line)

time_end= time.time()
print "Time elapsed: ", time_end - time_start

