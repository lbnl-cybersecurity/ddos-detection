import matplotlib.pyplot as plt
import os
import sys
dir_module = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
dir_module = os.path.join(dir_module, 'common_module')
sys.path.insert(0, dir_module)
from plot_module import compare_plot, load_data

infile = 'udp_pkts.txt'
udp_pkts = load_data(infile)
infile = 'ssdp_pkts.txt'
ssdp_pkts = load_data(infile)

y1, y2 = udp_pkts, ssdp_pkts
y2 = [y1[i] - y2[i] for i in range(len(y1))]
x = range(len(y1))
xlabel, ylabel = 'time interval', 'Packets'
legend = ['udp', 'udp - ssdp']
outfile = 'pkts_udp.png'
compare_plot(y1, y2, x, xlabel, ylabel, legend, outfile)


infile = 'udp_byts.txt'
udp_byts = load_data(infile)
infile = 'ssdp_byts.txt'
ssdp_byts = load_data(infile)

y1, y2 = udp_byts, ssdp_byts
y2 = [y1[i] - y2[i] for i in range(len(y1))]
x = range(len(y1))
xlabel, ylabel = 'time interval', 'Bytes'
legend = ['udp', 'udp - ssdp']
outfile = 'byts_udp.png'
compare_plot(y1, y2, x, xlabel, ylabel, legend, outfile)
