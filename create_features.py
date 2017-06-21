"""Create a dataset of features.

The dataset is a list of rows. 
The format of each row is:
    file_id, dst_ip, feature_one, feature_two, ..., feature_n
    
The features are per dst_ip based.

::
    usage: 
        edit the FEATURES_MAP to specify features to be included.
        python create_features.py

"""
import sys
import time
import logging

LOG = logging.getLogger(__name__)
logging.basicConfig(stream = sys.stdout, level = logging.DEBUG)

from nfreader import RecordReader, FIELDS
from features_one import get_pkts, get_byts, get_uniq_srcip, get_uniq_sas

idx_da = FIELDS.index("da")
idx_fileid = FIELDS.index("file_id")

#-------------------------------------------------------------#
"""Customize features_map."""
FEATURES_MAP = {
    "pkts" : get_pkts,
    "byts" : get_byts,
    "uniq_srcip": get_uniq_srcip,
    "uniq_sas": get_uniq_sas
}
#--------------------------------------------------------------#

def get_dstip(uniq_dstip, records):
    """Get all unique dst_ips captured within a time interval.
    
    :param uniq_dstip: A dictionary with key: dst_ip, values: features.
    :param records: A list of netflow records captured within a time interval. 
    
    """
    for record in records:
        da = record[idx_da]
        uniq_dstip[da] = {}

def update_feature(uniq_dstip, records, func, name):
    """A wrapper to call the feature function and save results.
    
    The dataset we create is row-based. 
    Each row has some aggregated features of a dst_ip appearing within
    this time interval.

    :param uniq_dstip: A dictionary with key: dst_ip, values: features.
    :param records: A list of netflow records captured within a time interval.
    :param func: The feature function.
    :param name: The feature name.

    """
    tmp_results = func(records)
    for da in uniq_dstip:
        if da in tmp_results:
            value = tmp_results[da]
        else:
            value = ''
        uniq_dstip[da][name] = value

def get_features(uniq_dstip, records):
    """A wrapper to calculate a number of features for the netflow records received
    within a time interval.
    
    :param uniq_dst_ip: A dictionary with key: dst_ip, values: features.
    :param records: A list of netflow records captured within a time interval.

    """
    for name, func in FEATURES_MAP.items():
        update_feature(uniq_dstip, records, func, name)

def listify_features(uniq_dstip, curr_file_id, rows):
    """Save feature results into row-based format.
    
    Each row: file_id, dst_ip, features...
    
    :param uniq_dstip: A dictionary with key: dst_ip, values: features.
    :param curr_file_id: The file_id of the current time interval.
    :param rows: A lists of saved results.

    :returns: The number of formatted results added to rows.
    """
    # Important!!! Sort the dst_ips for later consolidation among multiple outfiles. 
    da_lists = sorted(uniq_dstip.keys())
    # Important!!! Sort the feature names.
    feature_names = sorted(FEATURES_MAP.keys())

    counter = 0
    for da in da_lists:
        tmp_row  = [curr_file_id, da]
        for feature_name in feature_names:
            value = uniq_dstip[da][feature_name]
            tmp_row.append(value)
        rows.append(tmp_row)
        counter += 1
    return counter

def write_headers(outfile, mode):
    """Write column names in the beginning of outfile.

    :param outfile: The outfile.
    :param mode: Write mode ab/wb.
    """
    # Important!!! Sort the feature names.
    feature_names = sorted(FEATURES_MAP.keys())
    headers = ['curr_file_id', 'dst_ip'] + feature_names
    headers = ','.join(headers)
    ff = open(outfile, mode)
    ff.write(headers + '\n')
    ff.close()

def write2file(rows, outfile, mode):
    """Write results to the outfile.
    
    :param rows: A list of results to write to outfile.
    :param outfile: The outfile.
    :param mode: Write mode ab/wb.
    """
    LOG.info("Write results to file...")
    ff = open(outfile, mode)
    for row in rows:
        linestr = ','.join([str(k) for k in row])
        ff.write(linestr + '\n')
    ff.close()


def main(): 
    sqlite_file = 'research_data/ddos_event1.sqlite' 
    table_name = 'lbl_mr2' 
    outfile = "{0}_features_dataset.txt".format(table_name)

    # Counter for the number of time intervals.
    counter_one = 0
    # Counter for the number of total records in the table.
    counter_two = 0

    # Save the rows in the features dataset.
    rows = []
    # Trigger to write chunk of results to outfile
    wr_counter = 0
    chunk_size = 1000000
    # Is it the first time to write?
    wr_flag = False

    start = time.time()
    # Read from table.
    reader = RecordReader(sqlite_file, table_name)
    reader.read()

    for records in reader:
        counter_one += 1
        counter_two += len(records)
        curr_file_id = records[0][idx_fileid]
        
        # Get all dst_ips appearing within this time interval.
        uniq_dstip = {}
        get_dstip(uniq_dstip, records)
        
        # Calculate features 
        get_features(uniq_dstip, records)

        # Save intermediate results of this time interval
        wr_counter += listify_features(uniq_dstip, curr_file_id, rows)
         
        # Write intermediate results to outfile?
        if wr_counter > chunk_size:
            LOG.debug("Write %d rows to file, elapsed time: %f" % (chunk_size, time.time() - start))
            if not wr_flag:
                wr_flag = True
                write_headers(outfile, 'wb')
            write2file(rows, outfile, 'ab')           
            # Clear rows & wr_counter
            rows = []
            wr_counter = 0
    
    # Corner case
    if rows:
        write2file(rows, outfile, 'ab')
        
    print "Total number of time intervals: ", counter_one
    print "Total number of netflow records: ", counter_two
    end = time.time() 
    print "Time elapsed: ", end-start

if __name__ == "__main__":
    main()
