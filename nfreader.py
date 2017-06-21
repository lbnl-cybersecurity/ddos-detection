"""Read from the database. 

Deprecated: The old version used to pile up table-reading and analysis in one class, 
and perform multiple analysis within one run of reading from the table. 

In the new script, we decouple analysis from table-reading.

Usage::
    import RecordReader
    reader = RecordReader(sqlite_file, table_name)
    reader.read()
    for records in reader:
        print(records)

"""
import sys
import logging
import sqlite3
import numpy as np

# FIELDS.
FIELDS = [
    "sa",
    "da",
    "sp",
    "dp",
    "pr",
    "flg",
    "ipkt",
    "ibyt",
    "sas",
    "file_id"
]

class RecordReader(object):
    """RecordReader reads netflow records from the database.
    
    :param sqlite_file: The database file.
    :param table_name: The name of the table to read from.

    Example::
        reader = RecordReader(sqlite_file, table_name)
        reader.read()
        for records in reader:
            print(records)

    """
    LOGGER_NAME = "RecordReader"

    def __init__(self, sqlite_file, table_name):
        """Initialize with database file, table name."""
        self.sqlite_file = sqlite_file
        self.table_name = table_name
        self.logger = logging.getLogger(self.__class__.LOGGER_NAME)
        logging.basicConfig(stream = sys.stdout, level = logging.DEBUG)

        # Track the current file_id.
        self.file_id = 0
        self.set_fileid = False

        self.prev = []

    def sql_command(self):
        """The sql command to be issued to the table."""
        _columns = ','.join(FIELDS)
        _select_tmpl = 'SELECT %s from %s' % (_columns, self.table_name)
        self.logger.debug("sql command issued: %s" % (_select_tmpl, ))
        return _select_tmpl
    
    def read(self):
        """Get data from the table."""
        # Connecting to the database file.
        conn = sqlite3.connect(self.sqlite_file)
        c = conn.cursor()

        # Issue the sql command.
        _select_tmpl = self.sql_command()
        c.execute(_select_tmpl)
        self.content = c

    def next(self):
        """Return the list of netflow records received in the next time interval or None if EOF."""
        records = []
        if self.prev:
            records += self.prev
            self.prev= []

        for row in self.content:
            file_id = row[-1]
            # Initialize file_id for the first time.
            if not self.set_fileid:
                self.set_fileid = True
                self.file_id = file_id
            if file_id > self.file_id:
                self.prev.append(row)
                self.file_id = file_id
                return records
            elif file_id < self.file_id:
                self.logger.error("Records are out of order.")
            else:
                records.append(row)
        
        # Corner case: the records of the last time interval.
        if records:
            return records

        return None

    def __iter__(self):
        return iter(self.next, None)
