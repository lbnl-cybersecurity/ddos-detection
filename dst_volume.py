"""Dump a list of records to a csv file. Records format:
- file_id, dst_ip, src_ip, volume

The idea is that we read tables and output as much, as general 
and as raw information as possible. And leave analysis work offline
with the dump file and without querying the table.

Usage::
"""

import sqlite3
import numpy as np

class Solution(object):
    """Dump a list of records to a csv file.
    
    :param sqlite_file: The database file.
    :param table_name: The name of the table to read from.
    :param outfile: The outfile to write results to.
    :param logger: The logging module

    Example::
        import Solution
        sol = Solution(sqlite_file, table_name, outfile, logger)
        sol.run()

    """
    def __init__(self, sqlite_file, table_name, outfile, logger):
        """Initialize with database file, table name, outfile, and logger."""
        self.sqlite_file = sqlite_file
        self.table_name = table_name
        self.logger = logger
        self.outfile = outfile

        # Track the current file_id
        self.file_id = 0
        self.set_fileid = False

        # A dictionary with key: dst_ip and value: an inner dictionary,
        # The inner dictionary: key: src_ip and value: volume.
        self.da_volume = {}

        # Counter to trigger write
        self.wr_counter = 0
        # Flag: is this the first time to write?
        self.wr_flag = True
        # Hold final results before write
        self.results = []

    def sql_command(self):
        """The sql command to be issued to the table."""
        _select_tmpl = 'SELECT sa,da,ipkt,file_id from %s' % (self.table_name)
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

    def func(self, sa, da, ipkt):
        """Update current da-volume dictionary"""
        if not da in self.da_volume:
            self.da_volume[da] = {}
            self.da_volume[da][sa] = ipkt/1000
        else:
            if not sa in self.da_volume[da]:
                self.da_volume[da][sa] = ipkt/1000
            else:
                self.da_volume[da][sa] += ipkt/1000

    def dump(self):
        """Dump da_volume dictionary to formatted records list."""
        for da in da_volume:
            for sa in da_volume[da]:
                row = [self.file_id, da, sa, ipkt]
                self.results.append(row)
                self.wr_counter += 1
                if self.wr_counter % 5000 == 0:
                    self.write2file()
                    self.results = []
    
    def run(self):
        """The entry function."""
        # Connecting to the database file
        conn = sqlite3.connect(self.sqlite_file)
        c = conn.cursor()

        # Issue the sql command
        _select_tmpl = self.sql_command()
        c.execute(_select_tmpl)

        # Build records
        for row in c:
            sa, da, ipkt, file_id = row
            # Initialize file_id for the first time
            if not self.set_fileid:
                self.set_fileid = True
                self.file_id = file_id
            if file_id > self.file_id:
                self.dump()
                if self.file_id % 500 == 0:
                    self.logger.info("Processed %d files..." % (self.file_id))
                self.file_id = file_id
                self.da_volume = {}
            elif file_id < self.file_id:
                logger.error("Records are out of order") 
            self.func(sa, da, ipkt)

        # Do analysis for the records of the last file
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
    outfile = '{0}_dst_volume.txt'.format(table_name)
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
