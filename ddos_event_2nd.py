from base import Base
from math import log

class Solution(Base):
    options = ['sa', 'da', 'sp', 'dp', 'pr', 'flg', 'ipkt', 'ibyt', 'sas']
    bin_size = 5*60     # seconds

    def __init__(self, outfile, table_name, target_ip):
        super(Solution,self).__init__()
        # hold # of flows per epoch time
        self.results = []
        self.outfile = outfile
        self.curr_tr_epoch = 0
        self.curr_dict = {}
        self.table_name = table_name
        self.target_ip = target_ip

        # output format
        self.entropy_fields = []
        self.unique_fields = []
        self.count_fields = []

        # flag used when first time write headers of file
        self.write_file_headers = False

    def sql_command(self):
        cols = ','.join(self.options)
        _select_tmpl = 'SELECT %s,tr from %s where da = "%s" order by rowid' % (cols, self.table_name, self.target_ip)
        return _select_tmpl

    def init_file(self):
        # write column headers to outfile
        #headers = 'time,%s' % ('sa, sp, dp, pkts per flow, bytes per flow, total pkts, total bytes, total flows, distinct sa, distinct flows, distinct sp, distinct dp, distinct pkt size')
        headers = 'time,' + ','.join(self.entropy_fields + self.unique_fields + self.count_fields) 
        ff = open(self.outfile, 'wb')
        ff.write(headers+'\n')
        ff.close()

    def set_curr_tr_epoch(self, val):
        self.curr_tr_epoch = val

    def get_curr_tr_epoch(self):
        return self.curr_tr_epoch

    def write2file(self):
        grid = 500
        if len(self.results) % grid != 0:
            return
        print "Write results to file..."
        if not self.write_file_headers:
            self.init_file()
            self.write_file_headers = True

        ff = open(self.outfile, 'ab')
        for line in self.results:
            linestr = ','.join([str(k) for k in line])
            ff.write(linestr + '\n')
        self.results = []

    def count_num(self, field, num):
        if not field in self.count_fields:
            self.count_fields.append(field)

        if not field in self.curr_dict:
            self.curr_dict[field] = num
        else:
            self.curr_dict[field] += num

    def count_unique(self, field, val):
        if not field in self.unique_fields:
            self.unique_fields.append(field)

        if not field in self.curr_dict:
            self.curr_dict[field] = {}
        if not val in self.curr_dict[field]:
            self.curr_dict[field][val] = 1

    def count_entropy(self, field, val, num):
        if not field in self.entropy_fields:
            self.entropy_fields.append(field)

        if not field in self.curr_dict:
            self.curr_dict[field] = {}

        if not val in self.curr_dict[field]:
            self.curr_dict[field][val] = num
        else:
            self.curr_dict[field][val] += num

    def dump(self):
        row = [self.curr_tr_epoch]
        for field in self.entropy_fields:
            hx = 0
            total = sum([self.curr_dict[field][k] for k in self.curr_dict[field]])
            for k in self.curr_dict[field]:
                nx = self.curr_dict[field][k]
                px = nx/float(total)
                hx += -1*px*log(px,2)
            N0 = log(len(self.curr_dict[field]), 2)
            hx_norm = hx
            if N0!=0:
                hx_norm = hx/float(N0)
            row.append(hx_norm)
        for field in self.count_fields:
            if field in self.curr_dict:
                row.append(self.curr_dict[field])
            else:
                row.append(0)

        for field in self.unique_fields:
            row.append(len(self.curr_dict[field]))

        self.results.append(row)
        self.write2file()

    ### user-defined analysis functions
    def func(self,row):
        sa, da, sp, dp, pr, flg, ipkt, ibyt, sas, tr = row
        # '2016-01-31 00:00:00' string length = 19
        tr_epoch = self.epoch(tr[:19])
        # 5min bins
        tm_window_start = self.curr_tr_epoch
        tm_window_end = tm_window_start + self.bin_size
        if tr_epoch >= tm_window_end:
            # finish reading one nfcapd dump file, continue to the next
            self.dump()
            # reset 
            self.curr_dict = {}
            curr_tr_epoch = (tr_epoch - tm_window_end)/self.bin_size * self.bin_size + tm_window_end
            self.set_curr_tr_epoch(curr_tr_epoch)
            tm_window_start = self.get_curr_tr_epoch()
            tm_window_end = tm_window_start + self.bin_size

        if tr_epoch >= tm_window_start and tr_epoch < tm_window_end:
            # traffic volume
            self.count_num('ipkt', ipkt)
            self.count_num('flows', 1)
            self.count_num('ipkt_tcp', 0)
            self.count_num('ipkt_udp', 0)
            self.count_num('ipkt_icmp', 0)
            self.count_num('ipkt_tcp_80', 0)
            self.count_num('ipkt_tcp_443', 0)
            self.count_num('tcp_syn', 0)
            if pr == 'TCP':
                self.count_num('ipkt_tcp', ipkt)
                if dp == 80:
                    self.count_num('ipkt_tcp_80', ipkt)
                elif dp == 443:
                    self.count_num('ipkt_tcp_443', ipkt)
                if flg == '....S.':
                    self.count_num('tcp_syn', ipkt)
            elif pr == 'UDP':
                self.count_num('ipkt_udp', ipkt)
            elif pr == 'ICMP':
                self.count_num('ipkt_icmp', ipkt)
