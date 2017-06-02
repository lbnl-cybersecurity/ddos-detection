"""
    Calculate entropy over time, default period is set to 5mins
    Usage: python entropyOverTime.py    
"""
import sqlite3
import time
import sys
from math import log

bin_size = 5*60                   # seconds
pattern = '%Y-%m-%d %H:%M:%S'   # date_time format

# outer dict{ key: attribute; value: inner dict}
# inner dict{ key: distinct element; value: frequency}
curr_s_dict = {}
# time reference to divide into unit time slots
curr_tr_epoch = 0
# attributes for which to plot timeseries entropy 
options=[]

# file to save entropy results per unit time
outfile = ''
results = []    # hold entropy values
grid = 500

def epoch(date_time):
    ### convert time string to epoch time
    try:
        epoch = int(time.mktime(time.strptime(date_time, pattern)))
        return epoch
    except Exception as e:
        print "Error: ", str(e)

def write2file():
    global results

    if len(results) % grid != 0:
        return
    print "Write entropy results to file..."
    ff = open(outfile, 'ab')
    for line in results:
        linestr = ','.join([str(k) for k in line])
        ff.write(linestr+'\n')
    results = []

def dump():
    global results

    row = [curr_tr_epoch]
    ### calculate current entropy
    for field in options:
        hx = 0
        total = sum([curr_s_dict[field][k] for k in curr_s_dict[field]])
        for element in curr_s_dict[field]:
            nx = curr_s_dict[field][element]
            px = nx/float(total)
            hx += -1*px*log(px, 2)
        N0 = log(len(curr_s_dict[field]), 2)
        hx_norm = hx/float(N0)
        #print "Field:{0}, Entropy:{1}".format(field, hx_norm)
        row.append(hx_norm)
    results.append(row)
    write2file()

def count(field, element, num):
    if not field in curr_s_dict:
        curr_s_dict[field] = {}

    if not element in curr_s_dict[field]:
        curr_s_dict[field][element] = num
    else:
        curr_s_dict[field][element] += num

def entropy(row):
    global curr_tr_epoch, curr_s_dict

    ipkt, tr = row[-2:]
    # '2016-01-31 19:15:01' string length = 19
    tr_epoch = epoch(tr[:19])
    # 5min bins
    tm_window_start = curr_tr_epoch
    tm_window_end = tm_window_start + bin_size
    if tr_epoch >= tm_window_end:
        # finish reading one nfcapd dump file, continue to the next
        dump()
        # reset global & local variables
        curr_s_dict = {}
        curr_tr_epoch = (tr_epoch - tm_window_end)/bin_size*bin_size + tm_window_end
        tm_window_start = curr_tr_epoch
        tm_window_end = tm_window_start + bin_size

    if tr_epoch >= tm_window_start and tr_epoch < tm_window_end:
        for i, field in enumerate(options):
            count(field, row[i], ipkt)
    else:
        print "tr order error"

def main():
    global curr_tr_epoch, options, outfile

    sqlite_file = "ddos.sqlite"
    table_name = 'lbl_mr2'
    curr_tr_epoch = epoch("2016-01-31 00:00:00")
    options = ['sa', 'da', 'sp', 'dp']
    outfile = '{0}_entropy.txt'.format(table_name)

    # Write column headers to outfile
    headers = 'time,%s' % (','.join(options))
    ff = open(outfile, 'wb')
    ff.write(headers+'\n')
    ff.close()

    start_time = time.time()
    # Connecting to the database file
    conn = sqlite3.connect(sqlite_file)
    c = conn.cursor()

    # Iterate over the cursor
    cols = ','.join(options)
    _select_tmpl = 'SELECT %s,ipkt,tr from %s' % (cols, table_name)
    c.execute(_select_tmpl)
    for row in c:
        entropy(row)

    # calculate entropy for the records in the last file 
    dump()
    ff = open(outfile, 'ab')
    for line in results:
        linestr = ','.join([str(k) for k in line])
        ff.write(linestr+'\n')
    end_time = time.time()
    print "Elapsed time: ", end_time - start_time

if __name__ == "__main__":
    main()
