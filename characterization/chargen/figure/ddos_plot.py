import matplotlib.pyplot as plt

def load_data(infile):
    data = []
    with open(infile, 'rb') as ff:
        for line in ff:
            val = float(line.rstrip('\n'))
            data.append(val)
    return data

attack_type = 'chargen'
time_window = 300.0
cycle = plt.rcParams['axes.prop_cycle'].by_key()['color']

infile = '{0}_ddos_pkts.txt'.format(attack_type)
data = load_data(infile)

x = range(len(data))
# Tick every 4 hours
xticks = range(0, len(x)+48, 48)
xtick_labels = ['21:00:00', '01:00:00', '05:00:00', '09:00:00', '13:00:00', '17:00:00', '21:00:00', '01:00:00']
h = plt.figure()

axes = h.add_subplot(3,1,1)
data = [k/float(1000.0)/time_window for k in data]
lns1 = axes.plot(x, data, '--', color=cycle[0], label='left axis')
#axes.set_ylim([0, 100])
axes.xaxis.set_ticks(xticks)
axes.set_xticklabels(xtick_labels, visible=False)
#axes.set_xlim([0, len(x)])
axes.set_ylabel('Packet Rate (Kpps)')

infile = '{0}_ddos_byts.txt'.format(attack_type)
data = load_data(infile)
ax2 = axes.twinx()
data = [k*8.0/time_window/float(1000000.0) for k in data]
lns2 = ax2.plot(x, data, ':', color=cycle[1], label='right axis')
#ax2.set_xlim([0, len(x)])
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
#axes.set_xlim([0, len(x)])
axes.set_ylabel('Amplifiers')


infile = '{0}_ddos_dports.txt'.format(attack_type)
data = load_data(infile)
axes = h.add_subplot(3,1,3)
axes.plot(x, data)
axes.xaxis.set_ticks(xticks)
axes.set_xticklabels(xtick_labels, rotation=20)
#axes.set_xlim([0, len(x)])
axes.set_ylabel('Dst. Ports')

outfile = 'feature.png'
plt.savefig(outfile)
outfile = 'feature.svg'
plt.savefig(outfile, format='svg')

