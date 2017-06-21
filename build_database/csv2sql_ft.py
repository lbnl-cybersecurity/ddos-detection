#!/usr/bin/python
"""
    Load csv files into sqlite database
	Use for csv files created by the flow-print tool
	
	Steps for creating the database:
	1.  Use flow-split on the merged samples (flow-merge)
		to break data into 5 minute samples.
	2.  Use script to apply flow-print to each 5 minute file.
		This produces the csv file for each 5 minute sample.
	3.  Sort the 5 minutes samples and add to fileList.txt.
	4.  Use csv2sql_ft.py to add csv files to a database.
	
"""

import sqlite3
import csv
import sys
import os
import time

# Convert strings to int/float data type
options = [('TEXT', str), ('INTEGER', int), ('REAL', float)]
options = dict(options)
cast = []



def import_csv(conn, cursor, table_name, infile, file_id):
    with open(infile, 'rb') as ff:
        next(ff)
        csvData = csv.reader(ff)
        func = lambda line: [cast[i](x) for i, x in enumerate(line)]
        newData = [func(line) for line in csvData if len(line) == NO_NETFLOW_FIELDS]

        # Inserting rows
        _insert_tmpl = 'INSERT INTO %s VALUES (%s)' % (table_name, ','.join(['?']*len(cast)))

        cursor.execute('BEGIN TRANSACTION')
        for row in chunk:
                try:
                    cursor.execute(_insert_tmpl, row+[file_id])
                except Exception as e:
                    print "Error on line %s: %s" % (row, e)
        conn.commit()



def main():
    # Connecting to the database file
    sqlite_file = "dnsAmpl.db"
    conn = sqlite3.connect(sqlite_file)
    c = conn.cursor()

    # Creating a table
    table_name = "dnsAmpl"
    schema_file = 'ftFields.txt'
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

    # Count the number of input files so far
    counter = 0

    with open("fileList.txt", "r") as inFile:
      fileList = []
      for line in inFile:
        if "5min" in line:
                fileList.append(line.rstrip())

    #  Start processing each file, adding csv files to database


    for file in fileList:
        # insert each file with the count appended to the rows
        # need to identify which 5 minute sample it is from
        with open(file, "r") as inFile:
          firstLine = True
          chunk_counter = 0
          for line in inFile:
                if firstLine == False:
                        # Add the row to DB, append file count
                  # read csv items, then insert
                  row = line.rstrip('\n').split()
                  c.execute('''INSERT INTO dnsAmpl(sa,da,pr,sp,dp,octs,pkts,count)
                  VALUES(?,?,?,?,?,?,?,?)''', (row[0],row[1],row[2],row[3],row[4],row[5],row[6],counter))
                  chunk_counter += 1
                  if chunk_counter >= 10000:
                    conn.commit()
                    chunk_counter = 0
                firstLine = False
          conn.commit()
        conn.commit()
        print "file %d added" %(counter)
        counter += 1

    # Closing the connection to the database file
    conn.close()
            

if __name__== "__main__":
  main()