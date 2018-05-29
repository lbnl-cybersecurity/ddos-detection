from __future__ import print_function
import collections

class BaseDet(object):
    def __init__(self):
        # For Debug
        self.num_of_events = 0
        self.target_ips = collections.defaultdict(lambda:0)

        # Log file 
        self._log = None

    def set_logfile(self, fileobj):
        self._log = fileobj
    
    # Entry function
    def run(self, *args, **kwargs):
        # function to be overloaded in child class
        pass

    # Backend function handling alerts info
    def sendmsg(self, msg):
        #TODO: send message to another program via unix socket
        if self._log:
            print(msg, file = self._log)
            self._log.flush()
        else:
            print(msg)

    # For Debug Purpose
    def summary(self):
        print("Total number of ddos events: ", self.num_of_events)
        print("Total number of target ips: ", len(self.target_ips))
        if self._log:
            print("Total number of ddos events: ", self.num_of_events, file = self._log)
            print("Total number of target ips: ", len(self.target_ips), file = self._log)
        pairs = sorted(self.target_ips.items(), key = lambda x:x[1], reverse=True)
        for da,freq in pairs:
            print(da, freq)
            if self._log:
                print(da, freq, file = self._log)
        if self._log:
            self._log.flush() 
