"""Features: 
    No. of pkts per destination ip
    No. of bytes per destination ip
    No. of unique source ips per destination ip
    No. of ASes per destination ip
"""
from nfreader import FIELDS

# Field column index.
idx_sa = FIELDS.index('sa')
idx_da = FIELDS.index('da')
idx_ipkt = FIELDS.index('ipkt')
idx_ibyt = FIELDS.index('ibyt')
idx_sas = FIELDS.index('sas')

def get_pkts(records):
    # A dictionary 
    # key: dst_ip
    # values: No. of pkts toward dst_ip captured within this time interval.
    results = {}
    for record in records:
        da, ipkt = record[idx_da], record[idx_ipkt]
        # Remove amplification of 1:1000 sampling.
        if not da in results:
            results[da] = ipkt / 1000
        else:
            results[da] += ipkt / 1000
    return results

def get_byts(records):
    # A dictionary
    # key: dst_ip
    # values: No of bytes toward dst_ip captured within this time interval.
    results = {}
    for record in records:
        da, ibyt = record[idx_da], record[idx_ibyt]
        # Remove amplification of 1:1000 sampling.
        if not da in results:
            results[da] = ibyt / 1000
        else:
            results[da] += ibyt / 1000
    return results

def get_uniq_srcip(records):
    # A dictionary
    # key: dst_ip
    # values: No. of unique src_ips connect with dst_ip within time interval.
    results = {}
    for record in records:
        da, sa = record[idx_da], record[idx_sa]
        if not da in results:
            results[da] = {sa}
        else:
            results[da].add(sa)
    for da in results:
        results[da] = len(results[da])
    return results

def get_uniq_sas(records):
    # A dictionary
    # key: dst_ip
    # values: No. of unique sas's connect with dst_ip within time interval.
    results = {}
    for record in records:
        da, sas = record[idx_da], record[idx_sas]
        if not da in results:
            results[da] = {sas}
        else:
            results[da].add(sas)
    for da in results:
        results[da] = len(results[da])
    return results
