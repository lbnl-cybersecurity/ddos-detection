"""Tstat Fields"""
from tstatFields import Fields
tsFields = Fields
idx_sa_ts, idx_da_ts = Fields.index('c_ip'), Fields.index('s_ip')
idx_sport_ts, idx_dport_ts = Fields.index('c_port'), Fields.index('s_port')
idx_pkt_ts, idx_byt_ts = Fields.index('c_pkts_all'), Fields.index('c_bytes_uniq')
idx_syn_cnt = Fields.index('c_syn_cnt')
# Unit: ms
idx_epoch_ts, idx_durat_ts = Fields.index('last'), Fields.index('durat')

"""Flow-tools netflow v5 fields"""
from ftFields import Fields
ftFields = Fields
idx_sa_ft, idx_da_ft = Fields.index('srcaddr'), Fields.index('dstaddr')
idx_sport_ft, idx_dport_ft = Fields.index('srcport'), Fields.index('dstport')
idx_prot_ft = Fields.index('prot')
idx_pkt_ft, idx_byt_ft = Fields.index('dpkts'), Fields.index('doctets')
# Unit seconds
idx_epoch_ft = Fields.index('unix_secs')

"""NetFlow Fields"""
from nfFields import Fields
nfFields = Fields
idx_sa_nf, idx_da_nf, idx_sport_nf, idx_dport_nf = Fields.index('sa'), Fields.index('da'), Fields.index('sp'), Fields.index('dp')
idx_prot_nf, idx_flg_nf = Fields.index('pr'), Fields.index('flg')
idx_pkt_nf, idx_byt_nf = Fields.index('ipkt'), Fields.index('ibyt')
idx_durat_nf = Fields.index('td')
idx_epoch_nf = Fields.index('tr')

import re
import time
# Define parse error
class ParseError(Exception):
    pass

def parser(line):
    data = {}
    # First determine its encoding format
    ll = line.rstrip('\n').split(',')
    if len(ll) == len(ftFields):
        # flow-tools netflow v5 format
        data['sa'], data['da'] = ll[idx_sa_ft], ll[idx_da_ft]
        data['sport'], data['dport'] = int(ll[idx_sport_ft]), int(ll[idx_dport_ft])
        data['pkt'], data['byt'] = int(ll[idx_pkt_ft]), int(ll[idx_byt_ft])
        data['prot'] = int(ll[idx_prot_ft])
        data['epoch'] = float(ll[idx_epoch_ft])

        return data
    elif len(ll) == len(nfFields):
        # netflow format
        data['sa'], data['da'] = ll[idx_sa_nf], ll[idx_da_nf]
        data['sport'], data['dport'] = int(ll[idx_sport_nf]), int(ll[idx_dport_nf])
        data['pkt'], data['byt'] = int(ll[idx_pkt_nf]), int(ll[idx_byt_nf])
        prot, data['flg'] = ll[idx_prot_nf], ll[idx_flg_nf]
        # pattern: yyyy-mm-dd hh:mm:ss
        epoch_tr = re.findall('\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d', ll[idx_epoch_nf])[0]
        epoch_tr = time.mktime(time.strptime(epoch_tr, '%Y-%m-%d %H:%M:%S'))
        data['epoch'] = epoch_tr

        # encode verbal protocol to protocol number
        if prot == 'UDP':
            data['prot'] = 17
        elif prot == 'TCP':
            data['prot'] = 6
        else:
            data['prot'] = -100
        return data
    elif len(ll) == len(nfFields):
        # tstat format
        data['sa'], data['da'] = ll[idx_sa_ts], ll[idx_da_ts]
        data['sport'], data['dport'] = int(ll[idx_sport_ts]), int(ll[idx_dport_ts])
        data['pkt'], data['byt'] = int(ll[idx_pkt_ts]), int(ll[idx_byt_nf])
        data['durat'] = float(ll[idx_durat_ts])
        # Always TCP, cause we are using DTN TCP trace
        data['prot'] = 6
        return data

    # If can not be decoded 
    raise ParseError('Can not decode format of line')

