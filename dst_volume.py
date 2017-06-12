"""Distribution of traffic volume per destination ip."""

import sqlite3
import numpy as np

#from netaddr import IPNetwork, IPAddress
def filter_ip():
    """Subnets belong to ESnets or a Site."""
    import re
    esnets_sites= []
    pattern = "(\d+.\d+.\d+.\d+\/\d+)"

    infile = "ipv4_esnet_sites.txt"
    with open(infile, 'rb') as ff:
        for line in ff:
            match = re.findall(pattern, line)
            esnets_sites.append(match[0])
    return esnets_sites


def is_internal(da, esnets_sites):
    """Check if destination ip belongs to ESnets or a Site."""
    from netaddr import IPNetwork, IPAddress
    for subnet in esnets_sites:
        if IPAddress(da) in IPNetwork(subnet):
            return True
    return False
   

class Solution(object):
    """Calculate distribution of volume contribution over destination ip.
    
    :param sqlite_file: The database file.
    :param table_name: The name of the table to read from.
    :param outfile: The outfile to write results to.
    :param logger: The logging module

    Example::
        import Solution
        sol = Solution(sqlite_file, table_name, logger)
        sol.run()

    """
    # We use this trick to toggle between different dump functions
    version = 1

    def __init__(self, sqlite_file, table_name, outfile, logger):
        """Initialize with database file, table name, outfile, and logger."""
        self.sqlite_file = sqlite_file
        self.table_name = table_name
        self.logger = logger
        self.outfile = outfile

        # Track the current file_id
        self.file_id = 0
        self.set_fileid = False

        # Used for analysis within a unit time
        self.da_volume = {}

        # Counter to trigger write
        self.wr_counter = 0
        # Flag: is this the first time to write?
        self.wr_flag = True
        # Hold final results before write
        self.results = []

    def sql_command(self):
        """The sql command to be issued to the table."""
        _select_tmpl = 'SELECT da,ipkt,file_id from %s' % (self.table_name)
        return _select_tmpl

    def write2file(self):
        """Write results to the outfile."""
        self.logger.info("Write results to file...")
        mode = 'ab'
        if self.wr_flag:
            mode = 'wb'
            self.wr_flag = False

        ff = open(self.outfile, mode)
        for line in self.results:
            linestr = ','.join([str(k) for k in line])
            ff.write(linestr + '\n')
        ff.close() 

    def func(self, da, ipkt):
        """Update current da-volume dictionary"""
        if not da in self.da_volume:
            self.da_volume[da] = ipkt/1000
        else:
            self.da_volume[da] += ipkt/1000

    def dump_top_ips(self, topk):
        """Rank the destination ips based on traffic volume towards them.

        We set absolute volume threshold to be 10000 => 10 * 1000
        """
        items = sorted(self.da_volume.items(), key = lambda x:x[1], reverse=True)
        itmes = [k for k in items if k[1]>=20]
        dst_ips = [k[0] for k in items][:topk]
        self.results.append(dst_ips) 
        self.wr_counter += 1
        if self.wr_counter % 500 == 0:
            self.write2file()
            self.results = []
         
    def dump_cdf(self):
        """We have collected all records in a unit time. Do analysis now."""
        items = sorted(self.da_volume.items(), key = lambda x:x[1], reverse=True)
        volumes = [k[1] for k in items]
        for i in range(1, len(volumes)):
            volumes[i] = volumes[i] + volumes[i-1]
        
        # x_axis for the cdf plot; x_axis: rank
        x_a = np.arange(1,10)
        x_b = np.arange(10, 100, 10)
        x_c = np.arange(100, 1100, 100)
        x_axis = np.concatenate((x_a, x_b))
        x_axis = np.concatenate((x_axis, x_c))      

        # Calculate distribution of traffic volume contribution over destination ip.        
        cdf = [100] * len(x_axis)
        total_volume = volumes[-1]
        for idx, x in enumerate(x_axis):
            if x < len(volumes):
                cdf[idx] = volumes[x-1] / float(total_volume) * 100
       
        self.results.append(cdf)
        self.wr_counter += 1
        if self.wr_counter % 500 == 0:
            self.write2file()         
            self.results = []

    def dump(self):
        """Load different dump functions based on version number."""         
        if self.version == 1:
            self.dump_cdf()
        elif self.version == 2:
            self.dump_top_ips(50) 
 
    def run(self):
        """The entry function."""
        # Connecting to the database file
        conn = sqlite3.connect(self.sqlite_file)
        c = conn.cursor()

        # Issue the sql command
        _select_tmpl = self.sql_command()
        c.execute(_select_tmpl)


        # Setup ESnets subnets range
        esnets_sites = filter_ip()        
        for row in c:
            da, ipkt, file_id = row
            # Initialize file_id for the first time
            if not self.set_fileid:
                self.set_fileid = True
                self.file_id = file_id
            if file_id > self.file_id:
                self.dump()
                self.file_id = file_id
                self.da_volume = {}
            elif file_id < self.file_id:
                logger.error("Records are out of order")
            
            # Wondering if this is the reason that it is so slow...
            #if is_internal(da, esnets_sites):
            #    self.func(da, ipkt)                     
            self.func(da, ipkt)

        # Do analysis for the records in the last file
        if self.da_volume:
            self.dump()
            self.da_volume = {}
        if self.results:
            self.write2file()
            

def main():
    import logging
    import sys
    import time

    sqlite_file = 'ddos_event1.sqlite'
    table_name = 'lbl_mr2'
    #outfile = '{0}_cdf_volume_dstip.txt'.format(table_name)
    outfile = '{0}_top_volume_dstip.txt'.format(table_name)
    logger = logging.getLogger(__name__)
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

    start = time.time()    
    sol = Solution(sqlite_file, table_name, outfile, logger)
    sol.version = 2
    sol.run()
    end = time.time()
    logger.info("Time elapsed: %f" % (end-start))

if __name__ == "__main__":
    main()  
