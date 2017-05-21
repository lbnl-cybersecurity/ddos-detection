# ddos-detection

The data we have are nfcapd dump files, with filenames like nfcapd.YYYYMMDDHHMM. We use nfdump to convert these files into csv's.

Still not finding a clue about which netflow version these files are using although I manually read the bytes of the file head...But anyway, move on to process nfcapd dumps into csv's

nfTocsv.py converts nfcapd dump files to csv files.

Next step: import these csv files into a database. 
- import a single csv file into the database
- import a group of csv's into the database
- crosscheck number of records match 

There are three datasets collected from three routers:
- lbl router
  - 23,460,191 from direct counting csv files
  - 23,460,191 from counting the database entries
- eqx router 
- atla router


csv2sqlite.py imports csv files into a database.

General findings about nfdumped csv files:
- 48 fields
  - ts, te, td: time start (first packet seen of this flow), time end(last packet seen of this flow), time duration
  - sa, da, sp, dp, pr: source/destination address, source/destination port, protocol
  - flg: ------, 6 bits, TCP flags
  - fwd: forwarding status
  - stos, dtos: src/des TOS
  - ipkt, ibyt, opkt, obyt: incoming packets/bytes, outgoing packets/bytes
  - in, out: input/output interface SNMP number
  - sas, das: source/destination BGP AS
  - smk, dmk: source/destination mask
  - dir: direction, 0: ingress flow, 1: egress flow
  - nh, nhb: nexthop IP address, bgp next hop IP
  - svln, dvln: src/dst vlan label
  - ismc, odmc, idmc, osmc: input src, output dst, input dst, output src MAC
  - mpls1-10: MPLS label 1-10
  - cl, sl, al: client/server/application latency
  - ra, eng, exid: router IP, router engine type/id, exporter sysid
  - tr: time the flow was received by the controller

Starting with netflow traces collected from router lbl-mr2. This dataset contains sampled flows from 01/31/2016 - 02/13/2016 (2 weeks).
- other than day 02/11, which has 278 dump files, each day has 288 files; 288 = 24*60/5
- on day 02/11, files are missing between 10:15 and 11:10 (nfcapd.201602111110.csv is next to nfcapd.201602111015.csv)

Initial findings about this data:
- The nfcapd dump files are divided into 5min bins, based on the 'tr time': time the flow was received by the controller
   - Ex. dump file with timestamp 2016/01/31 19:15, includes netflow records received between 19:15 and 19:20
   - We could calculate the deviation of the exact time the flow occurs and the observed time window.
- Non-informative fields:
  - fwd: forwarding status; The values under 'fwd' are ALL 0, meaning unknown [(1)].
  - opkt/obyt: output packets, bytes; The values under 'opkt/obyt' are ALL 0.
  - dtos: the value is 0 for the whole dataset
  - dir: flow direction: 0 - ingress flow, 1 - egress flow [(1)]; The values under 'dir' are ALL 0. 
  - nhb: the value is 0.0.0.0 for the whole dataset
  - svln/dvln: 0/0 for the whole dataset
  - ismc/odmc/idmc/osmc: the value is 00:00:00:00:00:00 for the whole dataset
  - mpls1-10: 0-0-0 for the whole dataset
  - cl/sl/al: client/server/application latency; The values under 'cl/sl/al' are ALL 0.
  - ra, eng, exid: only one value is listed under these fields for the whole dataset.

[(1)]:http://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html

There might be a bug in the code as "select" statement is not guaranteed to return rows in order of insertion.
- re-create the table, with a colume indicating insertion id, table name: lbl_mr2_test.
- crosscheck rows in each file:
  - from database
  - directly from csvfiles
  - They match.
    - Using old database created without the "insertion id" colume. 
    - Using "select" query without "order by".  
  - They match.
    - Using old database created without the "insertion id" colume.
    - Using "select order by rowid" query.
  - They match.
    - Using new database with "insertion id"
    - Using "select order by id" query

Next step: 
- plot entropy timeseries values as shown in this [paper](https://users.ece.cmu.edu/~vsekar/papers/imcfp04-nychis.pdf).
  - based on sa(source address), da(destination address), sp(source port), dp(destination port), and ipkt/ibyt, and tr
  - crosscheck number:
    - database: generate 4022 epochs (from 4022 unit time intervals), matching with 4022 nfcapd dump files collected from router lbl-mr2 
    - direct using csv files
- plot traffic volume vs time: pkts / bytes / flows


Found a great description document about ESnet [pdf](http://www.ece.virginia.edu/mv/MSthesis/tian-jin-thesis2013.pdf)
- For every new packet corresponding to flow F that is captured by the sampling process, NetFlow adds one to the flow-record packet count and increases the total size (bytes) by the packet-payload size. That explains the case: ipkt=1000, ibyt=21000. Because netflow only captures packet-payload size.
- In ESnet, the packet sampling rate is 1-in-1000, the active and inactive timeout intervals are 60 sec each, and NetFlow records are exported every 5 mins. Only as a reference, might change now.
- REN: research and education network

Further findings about this data:
- it seems like for "ipkt" field, the least report unit is 1000. The value under 'ipkt' is multiples of 1000.

Next step: 
- plot number of flows connecting to the target_ip over time
- All these entropy/volume can be treated as features. We have analyzed these features from the overal traffic perspective, but now we should look to see these features per destination. In this scenario, each flow is an instance with a particular feature pattern (like a dot in the feature space), then we can do clustering and find anomalies. 
- But how do you know if a feature is effective or not? Even for the same flow, features calcuated at different time intervals are representing different dots in the feature space. With this saying, plotting the feature over time for one particularly flow (with the same destination) can somewhat show us if this feature is a useful indicator for DDoS attack. 



