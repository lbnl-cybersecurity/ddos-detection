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
Initial findings about this data:
- dir: flow direction: 0 - ingress flow, 1 - egress flow [(1)]; The values under 'dir' are ALL 0. 
- opkt/obyt: output packets, bytes; The values under 'opkt/obyt' are ALL 0.
- fwd: forwarding status; The values under 'fwd' are ALL 0, meaning unknown [(1)].
- The nfcapd dump files are divided into 5min bins, based on the 'tr time': time the flow was received by the controller
   - Ex. dump file with timestamp 2016/01/31 19:15, includes netflow records received between 19:15 and 19:20
   - We could calculate the deviation of the exact time the flow occurs and the observed time window.
- cl/sl/al: client/server/application latency; The values under 'cl/sl/al' are ALL 0.

[(1)]:http://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html

Next step: plot entropy timeseries values as shown in this [paper](https://users.ece.cmu.edu/~vsekar/papers/imcfp04-nychis.pdf).
- based on sa(source address), da(destination address), sp(source port), dp(destination port), and ipkt/ibyt, and tr
- crosscheck number:
   - database
   - direct using csv files

