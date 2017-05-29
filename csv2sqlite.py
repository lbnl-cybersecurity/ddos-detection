#!/usr/bin/python
"""
    Load csv files into sqlite database

    :param sqlite_file: Name of sqlite file opened
    :param table_name: Database name to be written to
    :param user_fileslist: customized csv fileslist to load netflow records from
    
    Example:
        from scripts.lbl_mr2 import user_fileslist, user_sqlite_file, user_table_name
        ./csv2sqlite.py
    
    customized csv fileslist is feeded in this script 
"""
import csv
import sys
import os
import sqlite3
import time

""" Feed customized csv fileslist """
#from scripts.atla_eqx_ddos_span import user_fileslist, user_sqlite_file, user_table_name
from scripts.lbl_mr2 import user_fileslist, user_sqlite_file, user_table_name

# Convert strings to int/float data type
options = [('TEXT', str), ('INTEGER', int), ('REAL', float)]
options = dict(options)
cast = []
# Filter out stats reporting lines in csv files 
NO_NETFLOW_FIELDS = 48

# Global counter tracking file_id:
# Netflow records from the same file have the same file_id
file_id = 0
# Global indicator of router name
rname = ''

# Filter records
# Only select records whose dest_ip == target_ip
FLG_TARGET_FILTER = False
target_ip = '192.107.175.71'
dst_ip_index = 4

def chunks(data, rows=10000):
    """ Divides the data into 10000 rows each """
    for i in xrange(0, len(data), rows):
        yield data[i:i+rows]

def import_csv(conn, cursor, table_name, infile):
    global file_id, rname
    global FLG_TARGET_FILTER, target_ip, dst_ip_index
    with open(infile, 'rb') as ff:
        next(ff)
        csvData = csv.reader(ff)
        func = lambda line: [cast[i](x) for i, x in enumerate(line)]
        newData = [func(line) for line in csvData if len(line) == NO_NETFLOW_FIELDS]
        if FLG_TARGET_FILTER: 
            newData = [line for line in newData if line[dst_ip_index] == target_ip]
        divData = chunks(newData)

        # Inserting rows
        _insert_tmpl = 'INSERT INTO %s VALUES (%s)' % (table_name, ','.join(['?']*len(cast)))
        for chunk in divData:
            cursor.execute('BEGIN TRANSACTION')
            for row in chunk:
                try:
                    cursor.execute(_insert_tmpl, row+[file_id, rname])
                except Exception as e:
                    print "Error on line %s: %s" % (row, e)
            conn.commit()


def main():
    global file_id, rname
    # Connecting to the database file
    sqlite_file = user_sqlite_file
    conn = sqlite3.connect(sqlite_file)
    c = conn.cursor()

    # Creating a table
    table_name = user_table_name
    schema_file = 'nfdumpFields.txt'
    _columns = []
    with open(schema_file, 'rb') as ff:
        next(ff)
        for line in ff:
            col = line.rstrip('\n').split(',')
            field, datatype = col[0], col[1]
            cast.append(options[datatype])
            _columns.append("%s %s" % (field, datatype))
    _columns = ','.join(_columns)
    create_query = "CREATE TABLE IF NOT EXISTS %s (%s)" % (table_name, _columns)
    c.execute(create_query)

    # Committing changes
    conn.commit()

    csvFiles = user_fileslist
    print "Num of csv files to be imported into database: %d" % len(csvFiles)

    # Inserting records
    ### Test with a single csv file
    #csvFiles = ['test.csv']
    ### end Test
    start_time = time.time()
    total = len(csvFiles)
    grid = max(total/20, 1)
    spaces = total/grid
    count = 0
    for i, filename in enumerate(csvFiles):
        count += 1
        file_id = count

        # Get router name
        rootdir = '/research'
        rel_path = os.path.relpath(filename, rootdir)
        rname = rel_path.split('/')[0]
        
        import_csv(conn, c, table_name, filename)
        
        # Print progress bar
        if count % grid == 0:
            sys.stdout.write('\r')
            i = count/grid
            end_time = time.time()
            sys.stdout.write("[%-*s] %d%%, Time elapsed:%.4f" % (spaces, '='*i, i*100/spaces, end_time-start_time))
            sys.stdout.flush()
    sys.stdout.write('\n')            
    end_time = time.time()
    print "Total time elapsed: ", end_time - start_time

    # Closing the connection to the database file
    conn.close()

if __name__ == "__main__":
    main()

