"""Features for tcp-syn flooding.
    - No. of tcp-syn packets per destination ip
    - No. of unique src ips in tcp-syn packets toward a destination ip.
    - No. of unique src AS's in tcp-syn packets toward a destination ip.
"""

from nfreader import FIELDS

# Field column index.
idx_sa = FIELDS.index('sa')
idx_da = FIELDS.index('da')
idx_ipkt = FIELDS.index('ipkt')
idx_ibyt = FIELDS.index('ibyt')
idx_pr = FIELDS.index('pr')
idx_flg = FIELDS.index('flg')
idx_sas = FIELDS.index('sas')

def get_tcp_syn_pkts(records):
    # A dictionary
    # key: dst_ip
    # values: No. of tcp-syn packets toward dst_ip within this time interval.
    results = {}
    for record in records:
        da, ipkt, pr, flg = record[idx_da], record[idx_ipkt], record[idx_pr], record[idx_flg]
        if not da in results:
            results[da] = 0
        if pr == 'TCP' and flg == "....S.":
            # Remove amplification of 1:1000 sampling.
            results[da] += ipkt / 1000
    return results

def get_uniq_srcip_tcp_syn(records):
    # A dictionary
    # key: dst_ip
    # values: No. of unique source ips among tcp-syn packets toward dst_ip within this time interval.
    results = {}
    for record in records:
        da, sa, pr, flg = record[idx_da], record[idx_sa], record[idx_pr], record[idx_flg]
        if not da in results:
            results[da] = set()
        if pr == "TCP" and flg == "....S.": 
            results[da].add(sa)
    for da in results:
        results[da] = len(results[da])
    return results

def get_uniq_sas_tcp_syn(records):
    # A dictionary
    # key: dst_ip
    # values: No. of unique source AS's among tcp-syn packets to dst_ip within this time interval.
    results = {}
    for record in records:
        da, pr, flg, sas = record[idx_da], record[idx_pr], record[idx_flg], record[idx_sas]
        if not da in results:
            results[da] = set()
        if pr == "TCP" and flg == "....S.":
            results[da].add(sas)
    for da in results:
        results[da] = len(results[da])
    return results

	
