import matplotlib.pyplot as plt
import sys
import os
dir_module = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
dir_module = os.path.join(dir_module, 'common_module')
sys.path.insert(0, dir_module)
from plot_module import load_data

attack_type = 'ssdp'
time_window = 300.0
cycle = plt.rcParams['axes.prop_cycle'].by_key()['color']

infile = '{0}_ddos_pkts.txt'.format(attack_type)
data = load_data(infile)

x = range(len(data))
# Tick every 4 hours
xticks = range(0, len(x)+4, 4)
xtick_labels = ['10:00:00', '10:20:00', '10:40:00', '11:00:00', '11:20:00', '11:40:00', '12:00:00', '12:20:00']
h = plt.figure()

axes = h.add_subplot(3,1,1)
data = [k/float(1000.0)/time_window for k in data]
lns1 = axes.plot(x, data, '--', color=cycle[0], label='left axis')
#axes.set_ylim([0, 100])
axes.xaxis.set_ticks(xticks)
axes.set_xticklabels(xtick_labels, visible=False)
axes.set_xlim([0, len(x)])
axes.set_ylabel('Packet Rate (Kpps)')

infile = '{0}_ddos_byts.txt'.format(attack_type)
data = load_data(infile)
ax2 = axes.twinx()
data = [k*8.0/time_window/float(1000000.0) for k in data]
lns2 = ax2.plot(x, data, ':', color=cycle[1], label='right axis')
ax2.set_xlim([0, len(x)])
ax2.set_ylabel('Bit Rate (Mbps)')

lns = lns1 + lns2
labs = [l.get_label() for l in lns]
axes.legend(lns, labs, loc='best')

infile = '{0}_ddos_srcips.txt'.format(attack_type)
data = load_data(infile)
axes = h.add_subplot(3,1,2)
axes.plot(x, data)
axes.xaxis.set_ticks(xticks)
axes.set_xticklabels(xtick_labels, visible=False)
axes.set_xlim([0, len(x)])
axes.set_ylabel('Amplifiers')


infile = '{0}_ddos_dports.txt'.format(attack_type)
data = load_data(infile)
axes = h.add_subplot(3,1,3)
axes.plot(x, data)
axes.xaxis.set_ticks(xticks)
axes.set_xticklabels(xtick_labels, rotation=20)
axes.set_xlim([0, len(x)])
axes.set_ylabel('Dst. Ports')

outfile = 'feature.png'
plt.savefig(outfile)
outfile = 'feature.svg'
plt.savefig(outfile, format='svg')

