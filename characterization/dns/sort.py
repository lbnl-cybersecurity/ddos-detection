import os
import re
import heapq

infile = 'WSU/victim_WSUa.csv'
header = ''
with open(infile, 'rb') as ff:
    header = ff.readline()

files = []
for rootdir, subdirs, filenames in os.walk('.'):
    files += [os.path.join(rootdir,ff) for ff in filenames if re.findall('victim_.*csv$', ff)]
files = sorted(files)
print files

readers = []
for filename in files:
    r = open(filename, 'rb')
    readers.append(r)

from ftFields import Fields
idx_epoch = Fields.index('unix_secs')

h = []
for r in readers:
    r.readline()
    line = r.readline()
    ll = line.rstrip('\n').split(',')
    epoch = float(ll[idx_epoch])
    heapq.heappush(h, (epoch, line, r))

data = []
while h:
    epoch, line, r = heapq.heappop(h)
    data.append(line)
    # Insert a new line
    line = r.readline()
    if not line:
        continue
    ll = line.rstrip('\n').split(',')
    epoch = float(ll[idx_epoch])
    heapq.heappush(h, (epoch, line, r))

outfile = 'victim_dns_2015.csv'
with open(outfile, 'wb') as ff:
    ff.write(header)
    for line in data:
        ff.write(line)
