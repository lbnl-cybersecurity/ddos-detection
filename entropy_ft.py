
"""
    Calculate entropy over time, default period is set to 5mins  
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
target_count = 0 # how many packets sent to the target
target_flows = 0 # how many flows include the target destination

target = "204.38.0.0/21"


def write2file():
    global results

    #if len(results) % grid != 0:
    #    return
    print "Write entropy results to file..."
    ff = open(outfile, 'ab')
    for line in results:
        linestr = ','.join([str(k) for k in line])
        ff.write(linestr+'\n')
    results = []

def dump(count):
    global results
    global target_count
    global target_flows


    row = [count]
    print("calculating entropy for file %d",count)
    ### calculate current entropy
    for field in options:
                hx = 0
                total = sum([curr_s_dict[field][k] for k in curr_s_dict[field]])
                #print(total)
                for element in curr_s_dict[field]:
                        nx = curr_s_dict[field][element]
                        px = nx/float(total)
                        hx += -1*px*log(px, 2)
                N0 = log(len(curr_s_dict[field]), 2)
                if N0 != 0:
                        hx_norm = hx/float(N0)
                        #print "Field:{0}, Entropy:{1}".format(field, hx_norm)
                        row.append(hx_norm)
                        #print(row)
    row.append(target_flows)
    row.append(target_count)
    results.append(row)
    write2file()

def dump2(count):
    global results
    
    row = [count]
    print("Recording blank file", count)
    ### calculate current entropy
    for field in options:
                row.append(-1)
    row.append(target_flows)
    row.append(target_count)
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
    global curr_s_dict
    global current_file, prev_file
    global target_count
    global target_flows

    # 5min bins
    if current_file > prev_file:
        print("file number",current_file) 
        # finish reading one nfcapd dump file, continue to the next
        if row[5] == -1: # blank file
                dump2(current_file)
        else:
                dump(current_file)
        print(current_file)
        target_flows = 0
        target_count = 0
        # reset global & local variables
        curr_s_dict = {}

    if current_file == prev_file:
        if row[1] in target: # if the target is the destination, update the total count 
                        #print("contains target")
                        target_count += row[5]
                        target_flows += 1

        for i, field in enumerate(options):
            #print "counting"
            #count(field, row[i], row[5])
            if not field in curr_s_dict:
                curr_s_dict[field] = {}

            if not row[i] in curr_s_dict[field]:
                curr_s_dict[field][row[i]] = row[5]
            else:
                curr_s_dict[field][row[i]] += row[5]


def main():
    global options, outfile
    global current_file, prev_file

    sqlite_file = "dnsAmpl.db"
    table_name = 'dnsAmpl'
    options = ['count', 'sa', 'da', 'sp', 'dp', "pkts"]
    outfile = '{0}_entropy.txt'.format(table_name)

    # Write column headers to outfile
    headers = '%s' % (','.join(options))
    ff = open(outfile, 'wb')
    ff.write(headers+'\n')
    ff.close()

    start_time = time.time()
    # Connecting to the database file
    conn = sqlite3.connect(sqlite_file)
    c = conn.cursor()

    # Iterate over the cursor
    cols = ','.join(options)
    _select_tmpl = 'SELECT %s from %s' % (cols, table_name)
    c.execute(_select_tmpl)

    current_file = 0
    prev_file = 0
    blank_last_file = False
    for row in c:
        current_file = row[0]
                #print(row[5])
                #print(row[1])
                #print(row[2])
        entropy(row)
        if row[5] == -1:
                blank_last_file = True
        else:
                blank_last_file = False
        prev_file = current_file

    # calculate entropy for the records in the last file 
    if blank_last_file == False:
        dump(current_file)
        ff = open(outfile, 'ab')
        for line in results:
                linestr = ','.join([str(k) for k in line])
                ff.write(linestr+'\n')
    else:
        dump2(current_file)

if __name__ == "__main__":
    main()