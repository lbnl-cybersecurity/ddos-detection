# ddos-detection

The data we have are nfcapd dump files, with filenames like nfcapd.YYYYMMDDHHMM. We use nfdump to convert these files into csv's.

Still not finding a clue about which netflow version these files are using although I manually read the bytes of the file head...But anyway, move on to process nfcapd dumps into csv's

nfTocsv.py converts nfcapd dump files to csv files.

Next step: import these csv files into a database. 
- import a single csv file into the database
- import a group of csv's into the database
 - crosscheck number of records match: 
   - 23,460,191 from direct counting csv files
   - 23,460,191 from counting the database entries

csv2sqlite.py imports csv files into a database.

Starting with netflow traces collected from router lbl-mr2. This dataset contains sampled flows from 01/31/2016 - 02/13/2016.
Initial findings about the data:
- Dir:Flow direction: 0 - ingress flow, 1 - egress flow [ref](http://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html); The value of 'dir' is ALL 0. 

Next step: plot entropy timeseries values as shown in this [paper](https://users.ece.cmu.edu/~vsekar/papers/imcfp04-nychis.pdf).
- connect to the database

