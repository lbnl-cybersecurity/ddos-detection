"""Simple volume detector: 

We use the first few days as the training set. We first calculate the average
traffic rate of each destination ip, given that the destination ip belongs to 
the ESnets/Sites. If the average traffic rate of this dst_ip is larger than 
the absolute volume threshold, we records this dst_ip and its average traffic rate
as the its baseline. 

In the experiment period, for each time interval, we calculate the current traffic rate
of each destination that belongs to the subnet ranges of ESnets/Sites). For each des_ip, 
if its current volume is larger than the absolute volume threshold, we compare its current
volume with its historical baseline. If we records its baseline in the training set, and 
its current value is larger than alpha_trigger * baseline, then we rings an alarm. If we 
misses its baseline in the training set, we directly rings an alarm. 

Alarm aggregation: At time T, the current traffic volume exceeds alpha_trigger * baseline, 
if in the next time interval, the current traffic volume exceeds alpha_add * baseline, we 
extends the alarm to the next time interval up to a keep alive time (time_keepalive). 
By alarm aggregation we combine repeated alarms due to the same DDoS event into one. 

"""
import re
import sys
import numpy as np
import logging
from netaddr import IPNetwork, IPAddress

LOG = logging.getLogger(__name__)
logging.basicConfig(stream = sys.stdout, level=logging.DEBUG) 

# Absolute volume threshold: 20k packets/ 5 min
abs_volume_threshold = 20
# Alpha trigger
alpha_trigger = 2
alpha_add = 1
 
def filter_ip():
    """Subnets belong to ESnets or a Site."""
    esnets_sites = []
    pattern = "(\d+.\d+.\d+.\d+\/\d+)"
    infile = "ipv4_esnet_sites.txt"
    with open(infile, 'rb') as ff:
        for line in ff:
            match = re.findall(pattern, line)
            esnets_sites.append(match[0])
    return esnets_sites    

def is_internal(da, esnets_sites):
    """Check if destination ip belongs to ESnets or a Site."""
    for subnet in esnets_sites:
        if IPAddress(da) in IPNetwork(subnet):
            return True
    return False

def training(infile, end_file_id):
    """Calculate baseline of features for each destination ip."""
    # Calculate the average pckts/s for each destination ip.
    da_history = {}
    with open(infile, 'rb') as ff:
        for row in ff:
            file_id, da, sa, ipkt = row.rstrip('\n').split(',')
            file_id, ipkt = int(file_id), int(ipkt)
            # End of training period
            if file_id > end_file_id:
                LOG.debug("Breakout point: file_id = %d" % (file_id))
                break
            if not da in da_history:
                da_history[da] = ipkt
            else:
                da_history[da] += ipkt                         
    LOG.debug("No. of dst_ips in total: %d" % (len(da_history)))
    
    # Filter out dst_ips whose average bandwidth < abs_volume_threshold.
    large_da_history = {}
    for da in da_history:
        avg_da_volume = da_history[da] / float(end_file_id)
        if avg_da_volume > abs_volume_threshold:
            large_da_history[da] = {}
            large_da_history[da]['ipkt'] = avg_da_volume
    LOG.debug("No. of dst_ips larger than abs_volume_threshold: %d" % (len(large_da_history)))

    # Also record the avg number of source ips per monitoring interval
    da_srcips = {}
    for da in large_da_history:
        da_srcips[da] = []

    set_file_id = False
    curr_file_id = 0
    tmp_srcips = {}
    with open(infile, 'rb') as ff:
        for row in ff:
            file_id, da, sa, ipkt = row.rstrip('\n').split(',')
            file_id, ipkt = int(file_id), int(ipkt)
            if not set_file_id:
                set_file_id = True
                curr_file_id = file_id
            if file_id > curr_file_id:
                for da in da_srcips:
                    if not da in tmp_srcips:
                        da_srcips[da].append(0)
                    else:
                        da_srcips[da].append(len(tmp_srcips[da]))
                tmp_srcips = {}
            # End of traiing period
            if file_id > end_file_id:
                LOG.debug("Breakout point: file_id = %d" % (file_id))
                break
                       
            if da in large_da_history:
                if not da in tmp_srcips:
                    tmp_srcips[da] = {}
                    tmp_srcips[da][sa] = 1

    for da in large_da_history:
        avg = sum(da_srcips[da]) / float(len(da_srcips[da]))
        large_da_history[da]['srcips'] = avg
    return large_da_history    
 
def volume_detector(records, da_history):
    da_volume = {}
    for row in records:
        file_id, da, sa, ipkt = row
        if not da in da_volume:
            da_volume[da] = ipkt
        else:
            da_volume[da] += ipkt
    # Filter out dst_ips whose aggregated volume < abs_volume_threshold
    large_da = [da for da,vol in da_volume.iteritems() if vol > abs_volume_threshold]
    # Focus on dst_ips beloning to ESnets/Sites
    #large_da = [da for da in large_da if is_internal(da, esnets_sites)]
    
    #da_srcips = {}
    """
    for da in large_da:
        tmp = [row[2] for row in records if row[1] == da]   
        da_srcips[da] = len(set(tmp))
    """
    da_trigger = []
    for da in large_da:
        if not da in da_history:
            da_trigger.append(da)
        elif da_volume[da] > alpha_trigger * da_history[da]['ipkt']:
            da_trigger.append(da)
    return da_trigger
            
def experiment(infile, start_file_id, da_history):
    """If we don't care about historical values, and set the absolute volume threshold as
    the baseline for all destinations."""
    alarm_da = {}

    records = []
    set_file_id = False
    with open(infile, 'rb') as ff:
        for row in ff:
            file_id, da, sa, ipkt = row.rstrip('\n').split(',')
            file_id, ipkt = int(file_id), int(ipkt)
            if file_id > start_file_id:
                if not set_file_id:
                    set_file_id = True
                    curr_file_id = file_id
                if file_id > curr_file_id:
                    da_trigger = volume_detector(records, da_history)
                    for da in da_trigger:
                        alarm_da[da] = 1
                    if curr_file_id % 500 == 9:
                        LOG.debug("Processed file_id = %d" % (curr_file_id))
                    curr_file_id = file_id
                    records = []
                records.append([file_id, da, sa, ipkt])
    return alarm_da 

def main():
    infile = "lbl_mr2_dst_volume.txt"
    # Setup ESnets/Sites subnets range
    filter_ip() 

    end_file_id = 24*60/5*4
    LOG.info("No. of files used for training: %d" % (end_file_id))
    large_da_history = training(infile, end_file_id)  
    
    alarm_da = experiment(infile, end_file_id, large_da_history)
    print "Total number of unique alarm dst_ips in experiment period: ", len(alarm_da)

if __name__ == "__main__":
    main() 
