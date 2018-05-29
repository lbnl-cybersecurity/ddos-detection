from __future__ import print_function
import time
import os
import re

from det_ddos_synvol import Det_DDoS_SYNVOL

# Get files list
# Inpute directory where traffic log files are saved
basedir = 'data_tcp'
pattern = '.*\.csv$'
files = []
for rootdir, subdirs, filenames in os.walk(basedir):
    files += [os.path.join(rootdir, ff) for ff in filenames if re.match(pattern, ff)]
files = sorted(files)
lenth = len(files)


# Parameters
alpha, beta = 3, 0.99
days = 7
end_of_training = days* 24 * 60/5
abs_volume = 20000
time_aggregate = 5  # 5 * 5mins
busy_period = 3 # 15mins
syn_ratio_threshold = 50
logfile = 'synvol_log.txt'

det = Det_DDoS_SYNVOL(end_of_training, alpha, beta, abs_volume, time_aggregate, busy_period, syn_ratio_threshold)
fileobj = open(logfile, 'wb')
det.set_logfile(fileobj)

for idx, filename in enumerate(files):
    det.run(filename)
det.summary()
