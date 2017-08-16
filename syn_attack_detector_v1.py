import os
import subprocess
import shlex
import time
import datetime
import numpy as np
import matplotlib.pyplot as plt
import math
from statsmodels.tsa.seasonal import seasonal_decompose
from pandas import tseries
import pywt
import math


def topn_hosts(attribute, n): 
    os.chdir('/tmp/')
    os.system("/usr/local/bin/nfdump -M /Users/dghosal/Documents/My_Local_DDoS/lbl-mr2/2016/02/01:02:03:04:05:06:07:08:09:10:11:12:13 -R nfcapd.201602010000:nfcapd.201602132355 -o extended -n {0} -s dstip  \' flags S and not flags AFRPU' > /tmp/topn_syn_rx_hosts".format(n))
    with open('topn_syn_rx_hosts') as f:
        data = f.read()
        list_data = data.split('\n')
        #print(list_data)
        #print(len(list_data))
        topn_hosts = {}
        for i in range(len(list_data) - 8):
            x = list_data[i+2].split()
            #print(x)
            date_strings = x[0]
            hour_strings = x[1]
            year, month, day = date_strings.split("-")
            #print(year, month, day)
            d = datetime.date(int(year), int(month), int(day))
            unixtime = time.mktime(d.timetuple())
            hour, minutes, seconds = hour_strings.split(":")
            unixtime = unixtime + 3600*int(hour) + 60* int(minutes) + float(seconds)
            host_id = x[4]
            topn_hosts[host_id] = (int(x[5].split("(")[0]))
    return(topn_hosts)


def extract_data_to(ip_address): 
    os.system("/usr/local/bin/nfdump -M /Users/dghosal/Documents/My_Local_DDoS/lbl-mr2/2016/02/01:02:03:04:05:06:07:08:09:10:11:12:13 -R nfcapd.201602010000:nfcapd.201602132355 -o extended \'(proto TCP) and ((dst ip {0})) and (flags S and not flags AFRPU)\' > /tmp/{0}_to".format(ip_address))

def extract_data_from(ip_address): 
    os.system("/usr/local/bin/nfdump -M /Users/dghosal/Documents/My_Local_DDoS/lbl-mr2/2016/02/01:02:03:04:05:06:07:08:09:10:11:12:13 -R nfcapd.201602010000:nfcapd.201602132355 -o extended \'(proto TCP) and ((src ip {0})) and (flags SA and not flags FRPU)\' > /tmp/{0}_from".format(ip_address))

def extract_data_aggr(ip_address): 
    os.system("/usr/local/bin/nfdump -M /Users/dghosal/Documents/My_Local_DDoS/lbl-mr2/2016/02/01:02:03:04:05:06:07:08:09:10:11:12:13 -R nfcapd.201602010000:nfcapd.201602132355 -o extended \'(proto TCP) and ((dst ip {0}) or (src ip {0})) and (flags S or flags SA and not flags FRPU)\' > /tmp/{0}_aggr".format(ip_address))
    
    
def generate_time_series(ip_address, direction, ave_interval): 
    os.chdir('/tmp/')
    source_file = ip_address + "_" + direction
    with open(source_file) as f:
        data = f.read()
    syn_data = data.split('\n')
    syn_time_series = {}
    for i in (range(len(syn_data)-1)):
    #for i in range(20):
        x = syn_data[i].split()
        #print(x[0])
        if ((x[0].split("-")[0]) != '2016'): 
            continue
        date_strings = x[0]
        hour_strings = x[1]
        year, month, day = date_strings.split("-")
        #print(year, month, day)
        d = datetime.date(int(year), int(month), int(day))
        unixtime = time.mktime(d.timetuple())
        hour, minutes, seconds = hour_strings.split(":")
        unixtime = unixtime + 3600*int(hour) + 60* int(minutes) + float(seconds)
        toaddress = x[6]
        fromaddress = x[4]
        flags = x[7].replace('.',"")
        data = [toaddress, fromaddress, flags]
        syn_time_series[unixtime] = data
    # now we have the dictionary
    #print(syn_dic[1454918333.01] ) 
    #for key in sorted(syn_dict):
    #    print(key, syn_dict[key])
    # print("Number of records = {0}".format(len(syn_time_series.keys())))
    
    times = sorted(syn_time_series.keys())
    number_of_syns = len(times)
    x_times = []
    start = times[0]
    rate = []
    sum = 0
    for i in range(len(times)):
        sum = sum + 1
        if (times[i] - start)> ave_interval:
            rate.append(sum)
            x_times.append(times[i])
            start = times[i]
            sum = 0
    #fig = plt.figure(figsize=(15,10))
    #ax = fig.add_subplot(111)
    #plt.plot(x_times, rate)
    #plt.show()
    return (x_times, rate)

def generate_time_series_aggr(ip_address, direction, ave_interval): 
    os.chdir('/tmp/')
    source_file = ip_address + "_" + direction
    with open(source_file) as f:
        data = f.read()
    syn_data = data.split('\n')
    syn_time_series = {}
    for i in (range(len(syn_data)-1)):
    #for i in range(20):
        x = syn_data[i].split()
        #print(x[0])
        if ((x[0].split("-")[0]) != '2016'): 
            continue
        date_strings = x[0]
        hour_strings = x[1]
        year, month, day = date_strings.split("-")
        #print(year, month, day)
        d = datetime.date(int(year), int(month), int(day))
        unixtime = time.mktime(d.timetuple())
        hour, minutes, seconds = hour_strings.split(":")
        unixtime = unixtime + 3600*int(hour) + 60* int(minutes) + float(seconds)
        toaddress = x[6]
        fromaddress = x[4]
        flags = x[7].replace('.',"")
        data = [toaddress, fromaddress, flags]
        syn_time_series[unixtime] = data
    # now we have the dictionary
    #print(syn_dic[1454918333.01] ) 
    #for key in sorted(syn_dict):
    #    print(key, syn_dict[key])
    #print("Number of records = {0}".format(len(syn_time_series.keys())))
    
    times = sorted(syn_time_series.keys())
    number_of_syns = len(times)
    x_times = []
    start = times[0]
    rate = []
    sum = 0
    for i in range(len(times)):
        if (syn_time_series[times[i]][2] =='S'): 
            sum = sum + 1
        else: 
            sum = sum - 1
        if (times[i] - start)> ave_interval:
            rate.append(sum)
            x_times.append(times[i])
            start = times[i]
            sum = 0
    #fig = plt.figure(figsize=(15,10))
    #ax = fig.add_subplot(111)
    #plt.plot(x_times, rate)
    #plt.show()
    return (x_times, rate)

def decompose_timeseries(x_times, rate, ave_interval):
    cleaned_data = []
    for i in list(range(len(rate))):
        if math.isnan(rate[i]):
            print(i)
        else:
            cleaned_data.append(rate[i])
    rate = cleaned_data
    # We will look for seasonality over n days
    n_days = 1
    s_freq = n_days*(24*60/5) # 24*60/5 is the number of obvs per day
    results = seasonal_decompose(rate, freq=int(s_freq), model='additive')
    residual = results.resid
    trend = results.trend
    seasonality = results.seasonal
    #fig = plt.figure(figsize=(15,10))
    #plt.plot(results.trend)
    #plt.show()
    return(trend, seasonality, residual)

def wavlet_decomp_dc(input_data, sample_size, level): 
    # disconnected chunks
    data = []
    temp = []
    for i in list(range(len(input_data))):
        if math.isnan(input_data[i]):
            print(i)
        else:
            temp.append(input_data[i])
    data_len = len(temp)
    n = data_len // sample_size
    print(data_len, n)
    for i in list(range(n-1)):
        l_limit = sample_size*i 
        u_limit = l_limit + sample_size
        coeffs = pywt.wavedec(temp[l_limit:u_limit], "haar")
        data.append(list(coeffs[level]))
    print(data)
    
def wavlet_decomp_sw(input_data, sampel_size, level): 
    # sliding_window
    data = []
    temp = []
    for i in list(range(len(input_data))):
        if math.isnan(trend[i]):
            print(i)
        else:
            temp.append(input_data[i])
    data_len = len(temp)
    n = data_len // sample_size
    print(data_len, n)
    for i in list(range(data_len - sample_size)):
        l_limit = i 
        u_limit = l_limit + sample_size
        coeffs = pywt.wavedec(temp[l_limit:u_limit], "haar")
        data.append(list(coeffs[level]))
    return(data)
    print(data)
    

def basic_ip_address_filter(topn_hosts): 
    hosts_wo_bd = {}
    hosts_w_bd = {}
    for key in topn_hosts: 
        extract_data_from(key)
        os.chdir('/tmp/')
        source_file = key + "_from"
        with open(source_file) as f:
            data = f.read()
        syn_data = data.split('\n')
        for i in (range(len(syn_data)-1)):
        #for i in range(20):
            x = syn_data[i].split()
            if (x[0] == 'Summary:'): 
                temp = syn_data[i].replace(':',' ').split()
                t_flows = int(temp[3].split(',')[0])
                print(key, t_flows)
                if (t_flows == 0): 
                    hosts_wo_bd[key] = t_flows
                else: 
                    hosts_w_bd[key] = t_flows 
    return(hosts_wo_bd, hosts_w_bd)

def syn_attack_detector_simple(hosts_w_bd, threshold): 
    for key in hosts_w_bd: 
        extract_data_aggr(key)
        direction = 'aggr'
        xtimes, rate = generate_time_series_aggr(key, direction, 300)
        for i in list(range(len(rate))):
            if rate[i] > threshold: 
                print(key, xtimes[i], rate[i])
        