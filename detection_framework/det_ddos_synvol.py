from __future__ import print_function
import collections
import math
from sys import getsizeof

import os
import sys
dir_current = os.path.dirname(os.path.abspath(__file__))
dir_module = os.path.join(dir_current, 'common_module')
sys.path.insert(0, dir_module)

from detector_base import BaseDet
from parser import parser, ParseError

class Det_DDoS_SYNVOL(BaseDet):
    """
    Usage: 
	det = Det_DDoS_DNS(end_of_training, alpha, beta, abs_volume, time_aggregate, busy_period, syn_ratio_thresh)
    	fileobj = open(logfile, 'wb')
    	det.set_logfile(fileobj)

    	for filename in (infiles):
        	det.run(filename)
    	det.summary()
    """

    def __init__(self, end_of_training, alpha, beta, abs_volume, 
	time_aggregate, busy_period, syn_ratio_thresh):
        # Initialize father class
        BaseDet.__init__(self)

        # Attack-type specific parameters
        self.target_prot = 6    # TCP Protocol
	self.target_flg = '....S.'	# TCP-SYN flag
        self.syn_ratio_thresh = syn_ratio_thresh  # percent

        # Initialize parameters in algorithm
        self.end_of_training = end_of_training
        self.alpha, self.beta = alpha, beta
        self.abs_vol = abs_volume
        self.time_aggr = time_aggregate
        self.busy_perid = busy_period
        # TODO: absolute threshold to be periodically updated

        # control parameters
        self.counter = 0
        # TODO: change counter to real-time after debug
        self.mode = 'training'
        
        # Current file being processed
        self._curr_file = None
        # Current traffic of interest records saved here
        # TODO: do we need to save this?
        self._cache = []
        # Keep record of history per dst address
        self._avg = {}  # TCP packets
        self._syn_ratio_avg = {}    # TCP-SYN packet ratio 
        # Hold until number of successive threshold violations reaching time aggregate
        self._pre_alarms = {}
        

    def _cal_syn_ratio(self, filename, target_da):
        def _syn_condition_func(ll):
            prot, flg, da = ll['prot'], ll['flg'], ll['da']
            if prot == self.target_prot and da == target_da and flg == self.target_flg:
                return True
            return False

        val = 0
        with open(filename, 'rb') as ff:
            header = ff.readline()
            for line in ff:
                try:
                    ll = parser(line)
                except ParseError:
                    continue
                if _syn_condition_func(ll):
                    pkt, byt = ll['pkt'], ll['byt']
                    val += pkt
        return val


    def _condition_tcp(self, ll):
        # Specify traffic of interest to monitor
        # In this case, we monitor TCP traffic
        prot = ll['prot']
        if prot == self.target_prot:
            return True
        else:
            return False


    def _monitor(self, fileobj):
        tmp = collections.defaultdict(lambda:0)
        self._cache = []
        with open(fileobj, 'rb') as ff:
            header = ff.readline()
            for line in ff:
                try:
                    ll = parser(line)
                except ParseError:
                    continue
                da, pkt, byt = ll['da'], ll['pkt'], ll['byt']
                if self._condition_tcp(ll):
                    tmp[da] += pkt
                    # We only save traffic of interest
                    self._cache.append(line)
        return tmp

    def _training(self, fileobj):
        # Get count of toi per dst address of current time interval
        curr = self._monitor(fileobj)
        for da in curr:
            # For each dst address appearing in this interval
            if not da in self._avg:
                self._avg[da] = [curr[da], 1]
            else:
                total, freq = self._avg[da]
                total += curr[da]
                freq += 1
                self._avg[da] = [total, freq]

            #if curr[da] >= self.abs_vol:
            #    syn_pkt = self._cal_syn_ratio(self._curr_file, da)
            #    ratio = syn_pkt / float(curr[da]) * 100
            #    if not da in self._syn_ratio_avg:
            #        self._syn_ratio_avg[da] = [ratio, 1]
            #    else:
            #        total, freq = self._syn_ratio_avg[da]
            #        total += ratio
            #        freq += 1
            #        self._syn_ratio_avg[da] = [total, freq]

        if self.counter == self.end_of_training:
            #-------End of training-----------#
            # Calculate volume average as normal baseline
            for da in self._avg:
                total, freq = self._avg[da]
                self._avg[da] = [int(math.floor(total/float(freq)))]
            
            # To save memory, we trim those dst addresses whose volume is small
            keys = self._avg.keys()
            for da in keys:
                if self._avg[da][0] * self.alpha < self.abs_vol:
                    del self._avg[da]
            
            # Calculate syn ratio average as normal baseline
            #for da in self._syn_ratio_avg:
            #    total, freq = self._syn_ratio_avg[da]
            #    self._syn_ratio_avg[da] = [total/float(freq)]
            print("------------End of Training-------------\n", file = self._log)
            print("DEBUG: training ends at {0}, size of _avg dictionary: {1}\n".format(self.counter, getsizeof(self._avg)), file=self._log)
            #for da in self._syn_ratio_avg:
            #    ratio = self._syn_ratio_avg[da]
            #    print("DEBUG: after training, syn-ratio baseline for {0} is {1}\n".format(da, ratio))

    def _detecting(self, fileobj):
        # Get count of toi per dst address of current time interval
        curr = self._monitor(fileobj)
        # Debug message
        #msg = 'current time interval: {0}, file: {1}'.format(self.counter, self._curr_file)
        #self.sendmsg(msg)

        for da in curr:
            curr_val = curr[da]
            # For each dst address appearing in this interval
            flag, lasting_intervals = self._test_ddos(da, curr_val)
            if flag:
                # This is an DDoS event
                self.num_of_events += lasting_intervals
                self.target_ips[da] += lasting_intervals
                continue

    #----->> Entry function <<----------#
    def run(self, fileobj):
        self.counter += 1
        self._curr_file = fileobj
        # Debug message
        #msg = 'current time interval: {0}'.format(self.counter)
        #self.sendmsg(msg)

        if self.counter <= self.end_of_training:
            self.mode = 'training'
        else:
            self.mode = 'detecting'

        if self.mode == 'training':
            return self._training(fileobj)

        if self.mode == 'detecting':
            return self._detecting(fileobj)

    # Update EWMA average
    def _update_avg(self, da, curr_val):
        if not da in self._avg:
            # avg_val * alpha < abs_vol
            old_val = self.abs_vol / self.alpha
            new_val = self.beta * old_val + (1.0 - self.beta) * curr_val
            self._avg[da] = [new_val]
        else:
            old_val = self._avg[da][0]
            new_val = self.beta * old_val + (1.0 - self.beta) * curr_val
            self._avg[da] = [new_val]

        # In order to save space, we trim out da's with small volume
        if self._avg[da] * self.alpha < self.abs_vol:
            del self._avg[da]

    def _test_ddos(self, da, curr_val):
        # CORE ALGO: modified adaptive change detection
        # Define absolute volume threshold to reduce false positives
        # Define the number of successive threshold violations before signalling the alarm

        # Debug message 
        #msg = 'time interval: {0}, da: {1}, current volume: {2}, average volume: {3}'.format(self.counter, da, curr_val, avg_val)
        #self.sendmsg(msg)

        if da in self._pre_alarms:
            # _pe_alarms: (key: da), (value: [time_buff, lenth, val_buff, file_buff])
            # last_interval: last time interval when a possible DDoS attack occurs
            # lenth: successive time intervals violated so far
            # time_buff: time intervals when possible DDoS attack occur
            # val_buff: volume at the time in time_buff
            # file_buff: traffic file of time in time_buff 
            # file_buff: [(filename, mark=0)...], mark=1, file already processed by 
            # attack-type-specific detection function

            last_interval, lenth, time_buff, val_buff, file_buff = self._pre_alarms[da]
            if self.counter - last_interval > self.busy_perid:
                # Successive period breaks
                # if buff != [], then update buffered volume
                for val in val_buff:
                    self._update_avg(da, val)
                del self._pre_alarms[da]
        
        # Get history volume
        if not da in self._avg:
            avg_val = int(math.floor(self.abs_vol / float(self.alpha)))
        else:
            avg_val = self._avg[da][0]

        # Debug message 
        msg = 'time interval: {0}, da: {1}, current volume: {2}, average volume: {3}'.format(self.counter, da, curr_val, avg_val)
        self.sendmsg(msg)
        
        # If not trigger basic alarm condition
        if not (curr_val >= self.alpha * avg_val and curr_val >= self.abs_vol):
            if not da in self._pre_alarms:
                # This is not a DDoS attack
                # Update EWMA average
                self._update_avg(da, curr_val)
                #return (False, 0)
            else:
                # This da is registered as potentially ddosed
                # We hold on decision for this time interval
                last_interval, lenth, time_buff, val_buff, file_buff = self._pre_alarms[da]
                time_buff += [self.counter]
                val_buff += [curr_val]
                # -1: Mark this interval not trigger basic alarm condition
                file_buff += [(self._curr_file, -1)]
                self._pre_alarms[da] = [last_interval, lenth, time_buff, val_buff, file_buff]
            return (False, 0)
        else:
            # This interval is suspicious
            if not da in self._pre_alarms:
                # Start aggregate
                last_interval, lenth = self.counter, 1
                time_buff, val_buff = [self.counter], [curr_val]
                file_buff = [(self._curr_file, 0)]
                self._pre_alarms[da] = [last_interval, lenth, time_buff, val_buff, file_buff]
            else:
                last_interval, lenth, time_buff, val_buff, file_buff = self._pre_alarms[da]
                # We have "self.counter - last_interval <= self.busy_period
                # Extend the same successive period
                last_interval = self.counter
                lenth += 1
                time_buff += [self.counter]
                val_buff += [curr_val]
                file_buff += [(self._curr_file, 0)]
                self._pre_alarms[da] = [last_interval, lenth, time_buff, val_buff, file_buff]

        #last_interval, lenth, time_buff,  val_buff, file_buff = self._pre_alarms[da]
        # Debug message
        #msg = 'time interval: {0}, aggregate lenth: {1}'.format(self.counter, lenth)
        
        if lenth >= self.time_aggr:
            # Reach alarming condition of time aggregate
            # Now let's do attack-type specific detection to reduce false positives
            self._per_type_detection(da)

        if not da in self._pre_alarms:
            return (False, 0)
        last_interval, lenth, time_buff, val_buff, file_buff = self._pre_alarms[da]
        assert(self.counter >= last_interval)
        if self.counter > last_interval:
            # This current interval won't trigger alarm
            return (False, 0)

        alert_level = 'Level 2'
        short_dscrip = 'Possible DDoS attack'
        if lenth >= self.time_aggr:
            # Ready to report this DDoS attack
            for i, time_interval in enumerate(time_buff):
                msg = self.alertmsg(alert_level, short_dscrip, da, val_buff[i], avg_val, time_interval)
                self.sendmsg(msg)
            self._pre_alarms[da] = [last_interval, lenth, [], [], []]
            return (True, len(time_buff))
        else:
            # Not a DDoS attack
            return (False, 0)

    # Different DDoS attack types require different further analysis/
    # false-reduction algorithms.
    def _per_type_detection(self, da):
        # Repeat process in test_ddos function
        # Only we add second feature: syn ratio
        def _alarm_condition(da, curr_val, avg_val, filename):
            # Condition c1: volume change alarm
            c1 = (curr_val >= self.alpha * avg_val) and (curr_val >= self.abs_vol)
            # Condition c2: syn ratio alarm
            syn_val = self._cal_syn_ratio(filename, da)
            syn_ratio = syn_val / float(curr_val) * 100
            c2 = (syn_ratio >= self.syn_ratio_thresh)
            if c1 and c2:
                return True
            return False

        _last_interval, _lenth, _time_buff, _val_buff, _file_buff = self._pre_alarms[da]
        if _lenth > self.time_aggr:
            # We only need to check if the last entry passes per-type alarm condition
            # Get history volume
            if not da in self._avg:
                avg_val = int(math.floor(self.abs_vol / float(self.alpha)))
            else:
                avg_val = self._avg[da][0]

            curr_val, curr_filename = _val_buff[-1], _file_buff[-1][0]
            if _alarm_condition(da, curr_val, avg_val, curr_filename):
                # Do nothing
                return 
            else:
                # Reset last interval
                new_last_interval = _last_interval - len(_val_buff)
                self._pre_alarms[da] = [new_last_interval, _lenth, _time_buff, _val_buff, _file_buff]
                return

        # _lenth == self.time_aggr
        # Just reach time aggregate threshold
        del self._pre_alarms[da]
        for idx, (filename, mark) in enumerate(_file_buff):
            curr_interval, curr_val = _time_buff[idx], _val_buff[idx]
            curr_filename = filename
            if da in self._pre_alarms:
                last_interval, lenth, time_buff, val_buff, file_buff = self._pre_alarms[da]
                if curr_interval - last_interval > self.busy_perid:
                    for val in val_buff:
                        self._update_avg(da, val)
                    del self._pre_alarms[da]

	    # Get history volume
	    if not da in self._avg:
		avg_val = int(math.floor(self.abs_vol / float(self.alpha)))
	    else:
		avg_val = self._avg[da][0]

	    # If not trigger basic alarm condition
	    if not _alarm_condition(da, curr_val, avg_val, curr_filename):
		if not da in self._pre_alarms:
		    # This is not a DDoS attack
		    # Update EWMA average
		    self._update_avg(da, curr_val)
		else:
		    # This da is registered as potentially ddosed
		    # We hold on decision for this time interval
		    last_interval, lenth, time_buff, val_buff, file_buff = self._pre_alarms[da]
		    time_buff += [curr_interval]
		    val_buff += [curr_val]
		    # -1: Mark this interval not trigger basic alarm condition
		    file_buff += [(curr_filename, -1)]
		    self._pre_alarms[da] = [last_interval, lenth, time_buff, val_buff, file_buff]
	    else:
		# This interval is suspicious
		if not da in self._pre_alarms:
		    # Start aggregate
		    last_interval, lenth = curr_interval, 1
		    time_buff, val_buff = [curr_interval], [curr_val]
		    file_buff = [(curr_filename, 0)]
		    self._pre_alarms[da] = [last_interval, lenth, time_buff, val_buff, file_buff]
		else:
		    last_interval, lenth, time_buff, val_buff, file_buff = self._pre_alarms[da]
		    # Extend the same successive period
		    last_interval = curr_interval
		    lenth += 1
		    time_buff += [curr_interval]
		    val_buff += [curr_val]
		    file_buff += [(curr_filename, 0)]
		    self._pre_alarms[da] = [last_interval, lenth, time_buff, val_buff, file_buff]
        return

            

    def alertmsg(self, alert_level, short_dscrip, da, curr_val, avg_val, counter):
        header = '{0}: {1} '.format(alert_level, short_dscrip)
        body = ('to address {0}, current volume {1}, ' +
            'average volume {2}, @time {3}').format(da, curr_val, avg_val, counter)
        msg = header + body
        return msg

