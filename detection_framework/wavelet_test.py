import os
import subprocess
import shlex
import time
import datetime
import numpy as np
#import matplotlib.pyplot as plt
import math
#from statsmodels.tsa.seasonal import seasonal_decompose
#import pandas as pd
#from pandas import tseries
import pywt
import math
import socket
from os import walk
from os import listdir
from os.path import isfile, join

class G():
    WINDOW_SIZE = 144
    TOP_N = 10
       # Where is the nfdump command
    NF_COMMAND = "/global/homes/r/rkgegan/nfdump/bin/nfdump "
    
    # this is temporary trace_directory, I store the last days worth of trace files
    # when new samnple is received it will be stored here
    SCRATCH_FOLDER = "/global/homes/r/rkgegan/framework/wavelet_temp"
    
    # List of files.  This will contain a queue of files. New files will be 
    # added 
    #range_of_files = "nfcapd.201602010000:nfcapd.201602132355 "
    TRACE_DIRECTORY_PATH = '/Users/dghosal/Documents/My_Local_DDoS/lbl-mr2/2016/02'
    
    AGGREGATION_INTERVAL = 300
    
    DETECTION_THRESHOLD = 20

class Wavelet():
	def __init__(self):
		self.log_entry = ""
		self.list_of_files = []
		
	def topn_hosts(self, trace_string, n, scratch_folder): 
		os.chdir(scratch_folder)
		#if (os.path.isfile('topn_syn_rx_hosts') == False): 
		os.system("{0} -o extended -n {1} -s dstip  \' flags S and not flags AFRPU' > {2}/topn_syn_rx_hosts".format(trace_string, n, scratch_folder))
		with open('topn_syn_rx_hosts') as f:
			data = f.read()
			list_data = data.split('\n')
			#print(list_data)
			#print(len(list_data))
			topn_hosts = {}
			for i in range(len(list_data) - 8):
				x = list_data[i+2].split()
				ip_address = x[4]
				try:
					socket.inet_aton(ip_address)
					# legal
					#print(x)
					date_strings = x[0]
					hour_strings = x[1]
					year, month, day = date_strings.split("-")
					#print(year, month, day)
					d = datetime.date(int(year), int(month), int(day))
					unixtime = time.mktime(d.timetuple())
					hour, minutes, seconds = hour_strings.split(":")
					unixtime = unixtime + 3600*int(hour) + 60* int(minutes) + float(seconds)
					#print(x[5], x[6])
					volume_info = (x[5].split("(")[0])
					#print(isinstance(eval(volume_info), int))
					try:
						isinstance(eval(volume_info), int)
						volume = int(volume_info)
						topn_hosts[ip_address]  = volume
					
					except: 
						#print(x[5], x[6])
						multiplier = x[6].split("(")[0]
						if multiplier == "M":
							volume = int(eval(volume_info)*10**6)
	#                
							topn_hosts[ip_address] = volume
				except socket.error:
						# Not legal
						print("Not a VALID IP ADDRESS {0}".format(ip_address))

		return(topn_hosts)


	def extract_data_to(self, ip_address, trace_string, scratch_folder): 
		os.system("{1} -o extended \'(proto TCP) and ((dst ip {0})) and (flags S and not flags AFRPU)\' > {2}/{0}_to".format(ip_address, trace_string, scratch_folder))

	def extract_data_from(self, ip_address, trace_string, scratch_folder): 
		os.system("{1} -o extended \'(proto TCP) and ((src ip {0})) and (flags SA and not flags FRPU)\' > {2}/{0}_from".format(ip_address, trace_string, scratch_folder))

	def extract_data_aggr(self, ip_address, trace_string, scratch_folder): 
		#print(ip_address)
		#os.system("{1} -o extended \'(proto TCP) and ((dst ip {0}) or (src ip {0})) and (flags S or flags SA and not flags FRPU)\' > {2}/{0}_aggr".format(ip_address, trace_string, scratch_folder))
		os.system("{1} -o extended \'(proto TCP) and ((dst ip {0}) or (src ip {0})) and (flags S or flags SA and not flags FRPU)\' > {2}/{0}_aggr".format(ip_address, trace_string, scratch_folder))
		
		
	def generate_time_series(self, ip_address, direction, ave_interval, scratch_folder): 
		os.chdir(scratch_folder)
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

	def generate_time_series_aggr(self, ip_address, direction, ave_interval, trace_string, scratch_folder): 
		os.chdir(scratch_folder)
		source_file = ip_address + "_" + direction
		print(source_file)
		
		self.extract_data_aggr(ip_address, trace_string, scratch_folder)
		#print(" now open file \n")
		with open(source_file) as f:
			data = f.read()
		#print("FInished reading source file \n")
		syn_data = data.split('\n')
		 
		syn_time_series = {}
		
		print "len(syn_data) is %d" % (len(syn_data))
		for i in (list(range(1,len(syn_data),1))):
		#for i in range(20):
			x = syn_data[i].split()
			print(syn_data[i]) # is printing the help for nfdump, must mean command is not working right
			if ((x[0].split("-")[0]) != '2016'): 
				break
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
			if x[7] == '0xc2': 
				print("SYN + PSH + RST")
				flags = 'S'
				data = [toaddress, fromaddress, flags]
				syn_time_series[unixtime] = data
			else: 
				print(x[7])
				flags = x[7].replace('.',"")
				data = [toaddress, fromaddress, flags]
				syn_time_series[unixtime] = data
		# now we have the dictionary
		#print(syn_dic[1454918333.01] ) 
		#for key in sorted(syn_dict):
		#    print(key, syn_dict[key])
		#print("Number of records = {0}".format(len(syn_time_series.keys())))
		
		# There could be no syn records
		x_times = []
		rate = []
		if any(syn_time_series) == True: 
			times = sorted(syn_time_series.keys())
			#number_of_syns = len(times)
		
			start = times[0]
		
			sum = 0
			for i in range(len(times)):
				if (syn_time_series[times[i]][2] =='S'): 
					sum = sum + 1
				else: 
					sum = sum + 1
				if (times[i] - start)> ave_interval:
					rate.append(sum)
					x_times.append(times[i])
					start = times[i]
					sum = 0
		else:
			print "no syns found"
		#fig = plt.figure(figsize=(15,10))
		#ax = fig.add_subplot(111)
		#plt.plot(x_times, rate)
		#plt.show()
		return (x_times, rate)

	def decompose_timeseries(self, x_times, rate, ave_interval):
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

	def wavlet_decomp_dc(self, input_data, sample_size, level): 
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
		
	def wavlet_decomp_sw(self, input_data, sample_size, level): 
		# sliding_window
		data = []
		temp = []
		for i in list(range(len(input_data))):
			if math.isnan(input_data[i]):
				print(i)
			else:
				temp.append(input_data[i])
		data_len = len(temp)
		n = data_len // sample_size
		#print(data_len, n)
		for i in list(range(data_len - sample_size)):
			l_limit = i 
			u_limit = l_limit + sample_size
			coeffs = pywt.wavedec(temp[l_limit:u_limit], "haar")
			data.append(list(coeffs[level]))
		return(data)
		#print(data)
		

	def basic_ip_address_filter(self, topn_hosts, trace_string, scratch_folder): 
		print("Basic IP Filtering")
		hosts_wo_bd = {}
		hosts_w_bd = {}
		for key in topn_hosts:
			#print "this is" 
			print(key)
			#print "here"
			os.chdir(scratch_folder)
			source_file = key + "_from"
			if (os.path.isfile(source_file) == False): 
				self.extract_data_from(key, trace_string, scratch_folder)

			with open(source_file) as f:
				data = f.read()
			syn_data = data.split('\n')
			for i in (range(len(syn_data)-1)):
			#for i in range(20):
				x = syn_data[i].split()
				if (x[0] == 'Summary:'): 
					temp = syn_data[i].replace(':',' ').split()
					t_flows = int(temp[3].split(',')[0])
					#print(key, t_flows)
					if (t_flows == 0): 
						hosts_wo_bd[key] = t_flows
					else: 
						hosts_w_bd[key] = t_flows 
		return(hosts_wo_bd, hosts_w_bd)

	def syn_attack_detector_simple(self, hosts_w_bd, threshold): 
		for key in hosts_w_bd: 
			self.extract_data_aggr(key)
			direction = 'aggr'
			xtimes, rate = self.generate_time_series_aggr(key, direction, 300)
			for i in list(range(len(rate))):
				if rate[i] > threshold: 
					print(key, xtimes[i], rate[i])
		  

	def get_all_file_names(self, trace_directory_path, dir): 
		list_of_dirs = listdir(trace_directory_path)
		list_of_files  = []
		for dir in list_of_dirs: 
			list_of_files.extend(listdir(trace_directory_path + "/" + dir))
		return(list_of_dirs, list_of_files)


	def single_host_analysis(self, ip_address, trace_string, file_range, date): 

		#list_of_files = listdir(G.TRACE_DIRECTORY_PATH + "/" + str(date))
		
	#    print(len(list_of_files))
	#    print(list(range(0, (len(list_of_files) - G.WINDOW_SIZE), 1)))
	#    input("Press Enter to continue...")
		
	#    for i in list(range(0, (len(list_of_files) - G.WINDOW_SIZE), 1)): 
	#        file_range = list_of_files[i] + ":" + list_of_files[i+ G.WINDOW_SIZE - 1]
	#        
	#        print(file_range)
	#        
	#        # get the top 10 targets with respect to nuumber of flows 
	#        trace_string = G.NF_COMMAND + " -M " + G.TRACE_DIRECTORY_PATH + "/" + str(date) + " -R " + file_range
	#        # print(trace_string)
		x_times, rate = self.generate_time_series_aggr(ip_address, "aggr", G.AGGREGATION_INTERVAL, trace_string, G.SCRATCH_FOLDER)
			#print(rate) # removed x_times, from in front of rate
			
			#plt.plot(x_times, rate)
			#plt.show()
			
			#input("Press Enter to continue with wavelet")
		
		print rate	
		data = self.wavlet_decomp_sw(rate, 64, 3)
		print(data)  #data is empty?  Fix this.
			
		for part in data: 
			# This part is super simple. Need lot more work
			if max(part) > G.DETECTION_THRESHOLD:
				#plt.plot(x_times, rate)
				#plt.show()
				
				print("SYN FLOOD ATTACK in {0}".format(file_range))
				self.log_entry = "SYN FLOOD ATTACK in {0}".format(file_range)
				#input("Press Enter to continue...")
				#break
			else:
				print "nope"

	def run_wavelet(self):
	 
		# Get the list of directories 
		#list_of_dirs = listdir(G.TRACE_DIRECTORY_PATH)
		#list_of_dirs = ["07"]
		#print(list_of_dirs)
		
		#for now, run test only when we have a list of 144 files?  
		#seems like we need to change the functions a bit more.
		#144 = looking at 12 hour chunks?
		#for dir in list_of_dirs:
		#	list_of_files = listdir(G.TRACE_DIRECTORY_PATH + "/" + dir)
			
		# change this for loop, preserve i, update list to add files, only shift the list left after adding new file
		# to the list
		
		for i in list(range(len(self.list_of_files))): 
				if i <= G.WINDOW_SIZE:
					#print "not working, i is %d and WIN is %d" % (i, G.WINDOW_SIZE)
					continue
				else: 
					#print "works"
					start_filename = self.list_of_files[i].rfind('/') + 1
					second_name = self.list_of_files[i][start_filename:]
					file_range = self.list_of_files[i - G.WINDOW_SIZE] + ":" + second_name
					#self.list_of_files[i]
					
					#trace_string = G.NF_COMMAND + " -M " + G.TRACE_DIRECTORY_PATH + "/" + dir + " -R " + file_range
					trace_string = "/global/homes/r/rkgegan/nfdump/bin/nfdump "  + " -R " + file_range

					print(file_range)
					#topN = topn_hosts(trace_string, 10, G.SCRATCH_FOLDER)
					#topN = {"184.222.134.129":1}
					topN = {"188.240.101.40":1}
						
					for key in topN: 
							
						#ip_address = input("input ip_address")
						#date = input("Input date")
				
						self.single_host_analysis(key, trace_string, file_range, dir)
					self.list_of_files.pop(0)
