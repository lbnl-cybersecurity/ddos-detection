import sys
import os
dir_module = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
dir_module = os.path.join(dir_module, 'common_module')
sys.path.insert(0, dir_module)

from monitor import monitor, write2file
from attack_signature import target_ip, target_sport, target_prot

infile = 'target_udp_traffic.csv'
files = [infile]
time_interval = 300 # seconds

import time
time_start = time.time()

# Monitor UDP/CHARGEN packets/bytes to target ip per time interval
udp_pkts, udp_byts, chargen_pkts, chargen_byts = [], [], [], []
monitor(files, target_prot, 'ANY', target_ip, time_interval, udp_pkts, udp_byts)
monitor(files, target_prot, target_sport, target_ip, time_interval, chargen_pkts, chargen_byts)

datas = [udp_pkts, udp_byts, chargen_pkts, chargen_byts]
outfiles = ['udp_pkts.txt', 'udp_byts.txt', 'chargen_pkts.txt', 'chargen_byts.txt']
for i in range(len(datas)):
    data, outfile = datas[i], outfiles[i]
    write2file(data, outfile)

time_end = time.time()
print "Time elapsed: ", time_end - time_start
