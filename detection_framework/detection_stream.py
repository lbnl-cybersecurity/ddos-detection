# Basic DDoS detection system for streaming Netflow data
# Python Netflow collection code is adapted from [site], need to verify license or rewrite code
# Collects data from Netflow stream and runs detection tests every 5 minutes.
# Currently collects counts used to perform the entropy test and monitor flow volume.

# TODO:
# 1. Add tests for each type of attack available in our data.
# 2. Make it simple to add new detection tests.
# 3. Ensure the code is neat and easily updated, possibly separate files for different tests.
# 4. Implement alert logs.  Start by logging target, timestamp, and entropy/volume data.
# 5. Add additional information to the logs, such as the attack type.

import socket
import struct
import time
import sys
import collections
from math import log

from socket import inet_ntoa

SIZE_OF_HEADER = 24
SIZE_OF_RECORD = 48

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 2346))
flow_count = 0
start_time = 0
current_time = 0
test_count = 1

# Detection variables
bin_size = 5*60                   # seconds
pattern = '%Y-%m-%d %H:%M:%S'   # date_time format

# outer dict{ key: attribute; value: inner dict}
# inner dict{ key: distinct element; value: frequency}
curr_s_dict = {}
# time reference to divide into unit time slots
curr_tr_epoch = 0
# attributes for which to plot timeseries entropy 
options=['sa', 'da', 'sp', 'dp']

# file to save entropy results per unit time
outfile = 'ddosLog.txt'
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

    print("dump called 1")
    #destCounter = collections.Counter() # data structure for tracking flow volume
    topDest = 0
    topIP = 'empty'
          
    row = [count]
    print("calculating entropy for file %d",count)
    ### calculate current entropy
    for field in options:
                print(field)
                hx = 0
                total = sum([curr_s_dict[field][k] for k in curr_s_dict[field]])
                #print(total)
                for element in curr_s_dict[field]:
                        #  update destinationCounter to get top destinations
                        nx = curr_s_dict[field][element]

                        if field in "da":
                                if nx > topDest:
                                        topDest = nx
                                        topIP = element

                        px = nx/float(total)
                        hx += -1*px*log(px, 2)
                N0 = log(len(curr_s_dict[field]), 2)
                print(N0)
                
                if N0 != 0:
                        hx_norm = hx/float(N0)
                        # check thresholds here

                        #for element in curr_s_dict[field]:
                                #print(element)
                        print(hx_norm)
                        if field in "da" and hx_norm < 1: #0.25:
                                print(topIP,topDest)
                                print("Potential DDoS attack found")
                                #ff = open(outfile, 'ab')
                                print("Target is: ", topIP, " Volume", topDest)
                                print(" Entropy: ", hx)
                                print(" Potential DDoS attack found\n")
    
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
    global start_time
    global test_count

    # Calculate the entropy every 5 minutes
    # test a chunk of flows after enough time has passed
    # consider changing this to use the netflow timestamps
    if start_time == 0:
            start_time = row[0] #time.time()
    #print(row[0] - start_time)                  
    if row[0] - start_time > 300000/60:
            start_time = row[0]
            print("start",start_time)
            test_count += 1
            print("test number",test_count) 
                # finish reading one nfcapd dump file, continue to the next
            if row[5] == -1: # blank file
                dump2(test_count)
            else:
                print("dump reached")
                dump(test_count)
            print(current_file)
            target_flows = 0
            target_count = 0
            # reset global & local variables
            print("this is reached")
            curr_s_dict = {}
            

    else:
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
                #print(row[5],field)
            else:
                curr_s_dict[field][row[i]] += row[5]
def main():
    
    while True:
            global flow_count
            global start_time
            buf, addr = sock.recvfrom(1500)

            (version, count) = struct.unpack('!HH',buf[0:4])
            if version != 5:
                    print "NetFlow v5 required" # update this for v9
                    continue

            if count >= 1000 or count <= 0:
                    print "Count %s is invalid" % count
                    continue

            uptime = socket.ntohl(struct.unpack('I',buf[4:8])[0])
            epochseconds = socket.ntohl(struct.unpack('I',buf[8:12])[0])

            for i in range(0, count):
                    try:
                            base = SIZE_OF_HEADER+(i*SIZE_OF_RECORD)

                            nf_data = struct.unpack('!IIIIHH',buf[base+16:base+36])

                            # Just call the entropy function instead
                            ent_data = []
                            ent_data.append(nf_data[2]) # start time
                            ent_data.append(inet_ntoa(buf[base+0:base+4])) # source address
                            ent_data.append(inet_ntoa(buf[base+4:base+8]) # destination address
                            ent_data.append(nf_data[4]) # source port
                            ent_data.append(nf_data[5]) # destination port
                            ent_data.append(nf_data[0]) # packet count
                            #print(nfdata['pcount'])
                            entropy(ent_data)
                            
                            flow_count += 1
                    except:
                            continue

            # Do something with the netflow record..
            #print "%s:%s -> %s:%s count:%s" % (nfdata['saddr'],nfdata['sport'],nfdata['daddr'],nfdata['dport'],flow_count)

if __name__ == "__main__":
    main()

