# Test Application Module
import time
import sys
import re
import os
import datetime

from dot.base import app_manager
from dot.lib import hub
from dot.controller.handler import set_ev_cls
from dot.controller import nf_event

from fields import FIELDS


class TCPSynFlooding(app_manager.DotApp):
    def __init__(self, *args, **kwargs):
        super(TCPSynFlooding, self).__init__(*args, **kwargs)
        
        self.abs_thold1, self.abs_thold2 = 20, 10
        self.alpha1, self.alpha2 = 4, 4
        self.beta1, self.beta2 = 0.98, 0.98

        # Global stateful data structure keeping track of average mu for each dst_ip
        # A dictionary
        # key: dst_ip, value: average mean of each measured feature
        self.mu_states = {}

        # Use K time intervals to build normal behaviour profile.
        self.K, self.tc = 100, 0

    def start(self):
        super(TCPSynFlooding, self).start()

    @set_ev_cls(nf_event.NewFileEvent)
    def event_handler(self, ev):
        self.logger.debug("Received event %s at time %f", ev.filename, time.time())

        self.tc += 1
        if self.tc <= self.K:
            fileobj = open(ev.filename, 'rb')
            headers = fileobj.readline()
            self.profile_normal(fileobj)

        if self.tc == self.K: 
            self.logger.debug('Size of mu_states after profiling: %d', len(self.mu_states))

        if self.tc > self.K:
            if self.tc % 500 == 0:
                self.logger.info("Processed %d number of files...", self.tc) 
            pattern = r'(\d+)'
            fileobj = open(ev.filename, 'rb')
            headers = fileobj.readline()
            timestamp = re.findall(pattern, os.path.basename(ev.filename))[0]
            timestamp = datetime.datetime.strptime(timestamp, "%Y%m%d%H%M")
            timestamp = timestamp.strftime('%m/%d/%Y %H:%M')
            alert = self.detector_adaptive(fileobj, timestamp, self.tc)
            if alert:
                line =  ','.join([str(k) for k in alert]) + '\n'
                self.logger.info("Alert triggered: %s", line)

    def _get_measure(self, fileobj):
        # Save measurements of current time interval into a dictionary
        # key: dst_ip, value: a sub-dictionary (key: feature_name, value: value of feature)
        curr_stats = {}
        idx_sa, idx_da, idx_dp = FIELDS.index('sa'), FIELDS.index('da'), FIELDS.index('dp')
        idx_ipkt = FIELDS.index('ipkt')
        idx_pr, idx_flg = FIELDS.index('pr'), FIELDS.index('flg')
        for record in fileobj:
            try:
                record = record.rstrip('\n').split(',')
                sa, da, dp, ipkt, pr, flg = record[idx_sa], record[idx_da], record[idx_dp], record[idx_ipkt], record[idx_pr], record[idx_flg]
                ipkt = int(ipkt)
                if not da in curr_stats:
                    curr_stats[da] = {}
                    curr_stats[da]['num-tcp-syn-pkts'] = 0
                    curr_stats[da]['num-uniq-srcips'] = set()
                if pr == 'TCP' and flg == '....S.':
                    if dp == '80' or dp == '443':
                        # Remove amplification of 1:1000 sampling.
                        curr_stats[da]['num-tcp-syn-pkts'] += ipkt/1000
                        curr_stats[da]['num-uniq-srcips'].add(sa)
            except ValueError:
                #print record
                continue
            except IndexError:
                #print record
                continue
        return curr_stats

    def profile_normal(self, fileobj):
        # Get measurement for current time interval.
        curr_stats = self._get_measure(fileobj)

        for dst_ip in curr_stats:
            c1 = curr_stats[dst_ip]['num-tcp-syn-pkts']
            c2 = len(curr_stats[dst_ip]['num-uniq-srcips'])

            if not dst_ip in self.mu_states:
                # This is the first measurement for this dst_ip
                self.mu_states[dst_ip] = {}
                self.mu_states[dst_ip]['num-tcp-syn-pkts'] = c1
                self.mu_states[dst_ip]['num-uniq-srcips'] = c2
            else:
                # Update average mean using EWMA (exponential weighted moving average)
                self.mu_states[dst_ip]['num-tcp-syn-pkts'] = self.mu_states[dst_ip]['num-tcp-syn-pkts']*self.beta1 + (1-self.beta1)*c1
                self.mu_states[dst_ip]['num-uniq-srcips'] = self.mu_states[dst_ip]['num-uniq-srcips']*self.beta2 + (1-self.beta2)*c2

        for dst_ip in self.mu_states:
            if not dst_ip in curr_stats:
                self.mu_states[dst_ip]['num-tcp-syn-pkts'] = self.mu_states[dst_ip]['num-tcp-syn-pkts']*self.beta1 + (1-self.beta1)*0
                self.mu_states[dst_ip]['num-uniq-srcips'] = self.mu_states[dst_ip]['num-uniq-srcips']*self.beta2 + (1-self.beta2)*0

    def detector_adaptive(self, fileobj, timestamp, counter):
        # For each dst_ip, we collect measurements for these two features:
        #   - No. of tcp syn packets destined to port 80/443 of this dst_ip
        #   - No. of unique source ips among the tcp syn packets destined to port 80/443 of this dst_ip
        #
        # Define x_n to be the measurement of a feature for dst_ip
        # we signal an alarm with target = dst_ip, if
        #   - x_n >= (alpha + 1) * mu_(n-1)
        # where, 
        #   - alpha: the threshold pencentage above which we consider to be an alarm.
        #   - mu_n is the average value computed using EWMA of previous measurements:
        #       - mu_n = beta * mu_(n-1) + (1-beta)*x_n
        #       - beta is the EWMA factor. 
        # 
        # For each feature, we have a set of tuning parameters:
        #   - alpha1, beta1
        #   - alpha2, beta2
        # 
        # We also set absolute volume threshold to provide a lower bound on DDoS attacks.
        #   - abs_threshold1, abs_threshold2

        # Get measurement for current time interval
        curr_stats = self._get_measure(fileobj)

        # We trigger an alarm if measurement
        #   - >= absolute threshold
        #   - >= (alpha+1) * mu_(n-1)
        reports = []
        alert_ips = []
        attack_type = "tcp-syn-flooding"
        for dst_ip in curr_stats:
            c1 = curr_stats[dst_ip]['num-tcp-syn-pkts']
            c2 = len(curr_stats[dst_ip]['num-uniq-srcips'])

            # Check if we have history average mean stored for this dst_ip
            #   - If not:
            #       - The corresponding average mean is smaller than abs_threshold/(alpha+1).
            #       - By default, we set it to be abs_threshold / (alpha + 1).
            # We only keep track of dst_ips with larger feature values.
            if c1 >= self.abs_thold1 and c2 >= self.abs_thold2:
                if not dst_ip in self.mu_states:
                    # The average mean feature value is small at normal state
                    self.mu_states[dst_ip] = {}
                    self.mu_states[dst_ip]['num-tcp-syn-pkts'] = self.abs_thold1 / float(self.alpha1 + 1) - 0.01
                    self.mu_states[dst_ip]['num-uniq-srcips'] = self.abs_thold2 / float(self.alpha2 + 1) - 0.01

                mu1 = self.mu_states[dst_ip]['num-tcp-syn-pkts']
                mu2 = self.mu_states[dst_ip]['num-uniq-srcips']
                if c1 >= (self.alpha1 + 1) * mu1 and c2 >= (self.alpha2 + 1) * mu2:
                    reports.append([timestamp, counter, dst_ip, attack_type])
                    alert_ips.append(dst_ip)

        # Update average mean
        keys = self.mu_states.keys()
        for dst_ip in keys:
            if not dst_ip in curr_stats:
                self.mu_states[dst_ip]['num-tcp-syn-pkts'] = self.mu_states[dst_ip]['num-tcp-syn-pkts']*self.beta1 + (1-self.beta1)*0
                self.mu_states[dst_ip]['num-uniq-srcips'] = self.mu_states[dst_ip]['num-uniq-srcips']*self.beta2 + (1-self.beta2)*0
            elif dst_ip in alert_ips:
                # If dst_ip is potentially being DDoSed, we keep its average mean of feature values unchanged.
                continue
            else:
                c1 = curr_stats[dst_ip]['num-tcp-syn-pkts']
                c2 = len(curr_stats[dst_ip]['num-uniq-srcips'])
                self.mu_states[dst_ip]['num-tcp-syn-pkts'] = self.mu_states[dst_ip]['num-tcp-syn-pkts']*self.beta1 + (1-self.beta1)*c1
                self.mu_states[dst_ip]['num-uniq-srcips'] = self.mu_states[dst_ip]['num-uniq-srcips']*self.beta2 + (1-self.beta2)*c2

        # Delete entries whose average mean is smaller than abs_threshold/(alpha+1)
        keys = self.mu_states.keys()
        for dst_ip in keys:
            mu1 = self.mu_states[dst_ip]['num-tcp-syn-pkts']
            mu2 = self.mu_states[dst_ip]['num-uniq-srcips']
            if not (mu1 *(self.alpha1+1) >= self.abs_thold1 and mu2*(self.alpha2+1) >= self.abs_thold2):
                self.mu_states.pop(dst_ip)
        return reports

