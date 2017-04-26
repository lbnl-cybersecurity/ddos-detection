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
- svlan, dvlan: src/dst vlan label
- ismc, odmc, idmc, osmc: input src, output dst, input dst, output src MAC
- mpls1-10: MPLS label 1-10
- cl, sl, al: client/server/application latency
- ra, eng, exid: router IP, router engine type/id, exporter sysid
- tr: time the flow was received by the controller


Starting with netflow traces collected from router lbl-mr2. This dataset contains sampled flows from 01/31/2016 - 02/13/2016.
- other than day 02/11, which has 278 dump files, each day has 288 files; 288 = 24*60/5
- on day 02/11, files are missing between 10:15 and 11:10 (nfcapd.201602111110.csv is next to nfcapd.201602111015.csv)

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

