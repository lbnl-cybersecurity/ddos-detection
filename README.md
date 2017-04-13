# ddos-detection

The data we have are nfcapd dump files, with files names like nfcapd.YYYYMMDDHHMM. We use nfdump to convert these files into csv's.

Still not finding a clue about which netflow version these files are using although I manually read the bytes of the file head...But anyway, move on to process nfcapd dumps into csv's

nfTocsv.py converts nfcapd dump files to csv files.
