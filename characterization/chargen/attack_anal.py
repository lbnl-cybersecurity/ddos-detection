import sys
import os
dir_module = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
dir_module = os.path.join(dir_module, 'common_module')
sys.path.insert(0, dir_module)

from monitor import monitor, monitor_srcip, monitor_dport
from monitor import write2file
from attack_signature import target_ip, target_sport, target_prot, attack_type

infile = 'target_udp_traffic.csv'
files = [infile]

time_interval = 300 # seconds
pkts, byts, srcips, dports = [], [], [], []
monitor(files, target_prot, target_sport, target_ip, time_interval, pkts, byts)
monitor_dport(files, target_prot, target_sport, target_ip, time_interval, dports)
monitor_srcip(files, target_prot, target_sport, target_ip, time_interval, srcips)

datas = [pkts, byts, srcips, dports]
outfiles = ['{0}_ddos_pkts.txt'.format(attack_type), '{0}_ddos_byts.txt'.format(attack_type), '{0}_ddos_srcips.txt'.format(attack_type), '{0}_ddos_dports.txt'.format(attack_type)]
for i in range(len(datas)):
    data, outfile = datas[i], outfiles[i]
    write2file(data, outfile)
