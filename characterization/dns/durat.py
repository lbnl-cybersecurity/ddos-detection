"""
    Understanding fiels:
    - sysup
    - first
    - last
    - epoch
"""
"""Flow-tools netflow v5 fields"""
from ftFields import Fields
# Unit miliseconds
idx_sysuptime, idx_first, idx_last = Fields.index('sysuptime'), Fields.index('first'), Fields.index('last')
# Unit seconds
idx_epoch = Fields.index('unix_secs')

def get_max_durat(files):
    # Calculate maximum flow duration: last packet time - first packet time
    # Calculate maximum offset: flow logging time - last packet time
    # Calculate dataset duration
    max_offset = 0; max_durat = 0
    start = None; end = start
    for filename in files:
	with open(filename, 'rb') as ff:
	    header = ff.readline()
	    for line in ff:
		ll = line.rstrip('\n').split(',')
		epoch_first, epoch_last, epoch_sysup = int(ll[idx_first]), int(ll[idx_last]), int(ll[idx_sysuptime])
		epoch = int(ll[idx_epoch])
                
                if not start:
                    start = epoch
                end = epoch

		# The epoch time when last packet of the flow was received
		assert epoch_sysup >= epoch_last
		offset = int((epoch_sysup - epoch_last)/float(1000))
		max_offset = max(offset, max_offset)

		durat = int((epoch_last - epoch_first)/float(1000))
		max_durat = max(durat, max_durat)
    return (max_offset, max_durat, end-start)

#--------Main------Program--------#
import os
import re

infile = 'target_udp_traffic.csv'
files = [infile]

max_offset, max_durat, dataset_durat = get_max_durat(files)

print max_offset
print max_durat
print "dataset duration: ", dataset_durat


# tr: time receiving this record
# tl: time receiving last packet of this flow
# max(tr-tl) is 60 seconds
#
# tr is always greater than tl
# tf: time receiving first packet of this flow
# max(tl-tf) is 60 seconds
