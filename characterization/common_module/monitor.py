from parser import parser, ParseError
#------------------------------------#
def monitor_dport(files, target_prot, target_sport, target_ip, time_interval, data_dports):
    # Monitor traffic of interest: number of dst ports per time interval of target ip
    tmp_dport = set()
    start = None
    for filename in files:
        with open(filename, 'rb') as ff:
            header = ff.readline()
            for line in ff:
                try:
                    ll = parser(line)
                except ParseError:
                    print "ParseError: not valid line: {0}".format(line)
                    break
                sa, da, sport, dport, prot = ll['sa'], ll['da'], ll['sport'], ll['dport'], ll['prot']
                epoch = ll['epoch']

                if not start:
                    start = epoch
                if start <= epoch < start + time_interval:
                    if da == target_ip and sport == target_sport and prot == target_prot:
                        tmp_dport.add(dport)	
                else:
                    while epoch >= start + time_interval:
                        data_dports.append(len(tmp_dport))
                        start += time_interval
                        tmp_dport = set()
                    if da == target_ip and sport == target_sport and prot == target_prot:
                        tmp_dport.add(dport)
    data_dports.append(len(tmp_dport))


#------------------------------------#
def monitor_srcip(files, target_prot, target_sport, target_ip, time_interval, data_srcips):
    # Monitor traffic of interest: number of srcips per time interval of target ip
    tmp_srcip = set()
    start = None
    for filename in files:
        with open(filename, 'rb') as ff:
            header = ff.readline()
            for line in ff:
                try:
                    ll = parser(line)
                except ParseError:
                    print "ParseError: not valid line: {0}".format(line)
                    break
                sa, da, sport, dport, prot = ll['sa'], ll['da'], ll['sport'], ll['dport'], ll['prot']
                epoch = ll['epoch']

                if not start:
                    start = epoch
                if start <= epoch < start + time_interval:
                    if da == target_ip and sport == target_sport and prot == target_prot:
                        tmp_srcip.add(sa)	
                else:
                    while epoch >= start + time_interval:
                        data_srcips.append(len(tmp_srcip))
                        start += time_interval
                        tmp_srcip = set()
                    if da == target_ip and sport == target_sport and prot == target_prot:
                        tmp_srcip.add(sa)
    data_srcips.append(len(tmp_srcip))

#-------------------------------------#
def monitor(files, target_prot, target_sport, target_ip, time_interval, data_pkts, data_byts):
    # Monitor traffic of interest: pkts/byts per time interval of target ip
    # Time starts from the beginning of the file.
    any_prot, any_sport, any_ip = False, False, False

    if target_sport == 'ANY':
        any_sport = True

    #data_pkts = []; data_byts = []
    tmp_pkts, tmp_byts = 0, 0
    start = None
    for filename in files:
        with open(filename, 'rb') as ff:
            header = ff.readline()
            for line in ff:
                try:
                    ll = parser(line)
                except ParseError:
                    print "ParseError: not valid line: {0}".format(line)
                    break
                sa, da, sport, dport, prot = ll['sa'], ll['da'], ll['sport'], ll['dport'], ll['prot']
                pkts, byts = ll['pkt'], ll['byt']
                epoch = ll['epoch']

                if not start:
                    start = epoch
                if start <= epoch < start + time_interval:
                    if (da == target_ip or any_ip) and (sport == target_sport or any_sport) and (prot == target_prot or any_prot):
                        tmp_pkts += pkts; tmp_byts += byts
                else:
                    while epoch >= start + time_interval:
                        data_pkts.append(tmp_pkts)
                        data_byts.append(tmp_byts)
                        start += time_interval
                        tmp_pkts, tmp_byts = 0, 0
                    if (da == target_ip or any_ip) and (sport == target_sport or any_sport) and (prot == target_prot or any_prot):
                        tmp_pkts += pkts; tmp_byts += byts
    data_pkts.append(tmp_pkts)
    data_byts.append(tmp_byts)

#------------------------------------#
def write2file(data, outfile):
    with open(outfile, 'wb') as ff:
        for val in data:
            ff.write(str(val) + '\n')

