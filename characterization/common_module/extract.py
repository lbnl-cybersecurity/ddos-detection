"""Flow-tools netflow v5 fields"""
from ftFields import Fields
idx_sa, idx_da = Fields.index('srcaddr'), Fields.index('dstaddr')
idx_sport, idx_dport = Fields.index('srcport'), Fields.index('dstport')
idx_dpkts, idx_dbyts = Fields.index('dpkts'), Fields.index('doctets')
idx_prot = Fields.index('prot')
# Unit seconds
idx_epoch = Fields.index('unix_secs')

from parser import parser, ParseError

def extract_udp(files, target_prot, target_ip):
    # Extract UDP traffic to/from target ip
    data = [] 
    header = ''
    with open(files[0], 'rb') as ff:
        header = ff.readline()
    data.append(header)

    for filename in files:
        with open(filename, 'rb') as ff:
            header = ff.readline()
            for line in ff:
                try:
                    ll = parser(line)
                except ParseError:
                    print "ParseError: not valid line: {0}".format(line)
                    break
                sa, da, prot = ll['sa'], ll['da'], ll['prot']
                if prot == target_prot:
                    if sa == target_ip or da == target_ip:
                        data.append(line)
    return data


def extract_toi(files, target_prot, target_sport, target_ip):
    # Extract traffic of interest (toi) SSDP/CHARGEN/DNS to target ip
    data = [] 
    header = ''
    with open(files[0], 'rb') as ff:
        header = ff.readline()
    data.append(header)
    
    for filename in files:
        with open(filename, 'rb') as ff:
            header = ff.readline()
            for line in ff:
                try:
                    ll = parser(line)
                except ParseError:
                    print "ParseError: not valid line: {0}".format(line)
                    break
                sa, da = ll['sa'], ll['da']
                sport, dport, prot = ll['sport'], ll['dport'], ll['prot']
                if prot == target_prot and sport == target_sport and da == target_ip:
                    data.append(line)
    return data


