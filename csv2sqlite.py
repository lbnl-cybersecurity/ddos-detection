#!/usr/bin/python
"""
    Load csv files into sqlite database
    Usage: ./csv2sqlite.py input-csv-dir
    
"""
import csv
import sys
import os
import sqlite3
import time

# Convert strings to int/float data type
options = [('TEXT', str), ('INTEGER', int), ('REAL', float)]
options = dict(options)
cast = []

def chunks(data, rows=10000):
    """ Divides the data into 10000 rows each """
    for i in xrange(0, len(data), rows):
        yield data[i:i+rows]

def import_csv(conn, cursor, table_name, infile):
    with open(infile, 'rb') as ff:
        next(ff)
        csvData = csv.reader(ff)
        func = lambda line: [cast[i](x) for i, x in enumerate(line)]
        newData = [func(line) for line in csvData if len(line) == len(cast)]
        divData = chunks(newData)

        # Inserting rows
        _insert_tmpl = 'INSERT INTO %s VALUES (%s)' % (table_name, ','.join(['?']*len(cast)))
        for chunk in divData:
            cursor.execute('BEGIN TRANSACTION')
            for row in chunk:
                try:
                    cursor.execute(_insert_tmpl, row)
                except Exception as e:
                    print "Error on line %s: %s" % (row, e)
            conn.commit()

def getFileList(rootDir, csvFiles):
    for dirname, subdirList, fileList in os.walk(rootDir, topdown=False):
        csvFiles += [os.path.join(dirname,k) for k in fileList if 'csv' in k and os.path.isfile(os.path.join(dirname, k))]

def main():
    # Connecting to the database file
    sqlite_file = 'ddos.sqlite'
    conn = sqlite3.connect(sqlite_file)
    c = conn.cursor()

    # Creating a table
    table_name = 'lbl_mr2'
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

    # Prepare a list of csv files to be imported to the database
    rootDir = sys.argv[1]
    csvFiles = []
    getFileList(rootDir, csvFiles)
    # Important! sort csvFiles list in time order
    csvFiles = sorted(csvFiles)
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

