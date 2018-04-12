import matplotlib.pyplot as plt
import sys
import os
dir_module = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
dir_module = os.path.join(dir_module, 'common_module')
sys.path.insert(0, dir_module)

from plot_module import compare_plot, load_data

attack_type = 'dns'

infile = 'udp_pkts.txt'
udp_pkts = load_data(infile)
infile = '{0}_pkts.txt'.format(attack_type)
dns_pkts = load_data(infile)

y1, y2 = udp_pkts, dns_pkts
y2 = [y1[i] - y2[i] for i in range(len(y1))]
x = range(len(y1))
xlabel, ylabel = 'time interval', 'Packets'
legend = ['udp', 'udp - {0}'.format(attack_type)]
outfile = 'pkts_udp.png'
compare_plot(y1, y2, x, xlabel, ylabel, legend, outfile)


infile = 'udp_byts.txt'
udp_byts = load_data(infile)
infile = '{0}_byts.txt'.format(attack_type)
dns_byts = load_data(infile)

y1, y2 = udp_byts, dns_byts
y2 = [y1[i] - y2[i] for i in range(len(y1))]
x = range(len(y1))
xlabel, ylabel = 'time interval', 'Bytes'
legend = ['udp', 'udp - {0}'.format(attack_type)]
outfile = 'byts_udp.png'
compare_plot(y1, y2, x, xlabel, ylabel, legend, outfile)
