import sys
import numpy as np
import matplotlib.pyplot as plt
from base import Base

class plot_entropy(Base):
    bin_size = 5*60     #seconds
    
    def __init__(self, infile, outfile):
        self.infile = infile
        self.outfile = outfile
        self.data = {}
        self.start_epoch, self.end_epoch = 0, 0
        self.options, self.legends, self.ylables, self.masks = [], [], [], []
        
    def set_start_epoch(self, val):
        self.start_epoch = val
    
    def set_end_epoch(self, val):
        self.end_epoch = val   

    def set_options(self, options):
        self.options = options

    def set_legends(self, legends):
        self.legends = legends

    def set_ylabels(self, ylabels):
        self.ylabels = ylabels

    def set_masks(self, masks):
        self.masks = masks

    def read_data(self):
        for infile in self.infile:
            with open(infile, 'rb') as ff:
                ff.next()
                for line in ff:
                    line = line.rstrip('\n').split(',')
                    line = [float(k) for k in line]
                    epoch = int(line[0])
                    if not epoch in self.data:
                        self.data[epoch] = line[1:]
                    else:
                        self.data[epoch] += line[1:]

    @classmethod
    def plot_misc(cls,axes,xmin,xmax,ylabel,legend):
        ylabelsize = 20
        xtick_labelsize, ytick_labelsize = 18, 14
        xmajor_ticklen, xminor_ticklen = 14, 7
        ymajor_ticklen = 7
        legend_size = 20
        
        # set xlim
        axes.set_xlim([xmin, xmax])
        # set xticks: every 6hours
        major_ticks = np.arange(xmin, xmax, 24*3600)
        minor_ticks = np.arange(xmin, xmax, 6*3600)
        axes.tick_params(axis = 'x', which='major', length = xmajor_ticklen, labelsize=xtick_labelsize)
        axes.tick_params(axis = 'x', which='minor', length = xminor_ticklen, labelsize=0)
        axes.tick_params(axis = 'y', which='major', length = ymajor_ticklen, labelsize=ytick_labelsize)
        axes.set_xticks(major_ticks)
        axes.set_xticks(minor_ticks, minor=True)
        strlabels = ['2/{0}'.format(k) for k in range(1,14)]
        xlabels = ['1/31'] + strlabels
        axes.set_xticklabels(xlabels)
        axes.set_ylabel(ylabel, fontsize=ylabelsize)
        axes.legend([legend], fontsize=legend_size)
       
    def plot(self):
        #width, height = 20.0, 40.0
        width = 20.0
        height = 5.0 * len(self.masks)
        fig = plt.figure(figsize=(width, height))
        x = [k for k in xrange(self.start_epoch, self.end_epoch, self.bin_size)]
        plotx = [k-self.start_epoch for k in x]
        
        for i, index in enumerate(self.masks):
            axes = fig.add_subplot(len(self.masks), 1, i+1)
            y = [0]*len(plotx)

            for j, val in enumerate(x):
                if val in self.data:
                    y[j] = self.data[val][index]
            plt.plot(plotx, y)
            self.plot_misc(axes, plotx[0], plotx[-1], self.ylabels[index], self.legends[index])
        fig.savefig(self.outfile)


def main():
    infile = sys.argv[1:]
    table_name = 'lbl_mr2'
    #outfile = "{0}_target_ip.png".format(table_name)
    outfile = "{0}_overall.png".format(table_name)
    start_epoch = Base.epoch("2016-01-31 00:00:00")
    end_epoch = Base.epoch("2016-02-14 00:00:00")
    
    sol = plot_entropy(infile, outfile)
    sol.set_start_epoch(start_epoch)
    sol.set_end_epoch(end_epoch)
    
    #options = ['sa', 'sp', 'dp', 'pkts per flow', 'bytes per flow', 'total pkts', 'total bytes', 'total flows', 'distinct sa', 'distinct flows', 'distinct sp', 'distinct dp', 'distinct pkt size']
    #legends = ['source address', 'source port', 'destination port', 'pkts per flow', 'bytes per flow', 'total pkts', 'total bytes', 'total flows', 'distinct sa', 'distinct flows', 'distinct sp', 'distinct dp', 'distinct pkt size']
    #ylabels = ['entropy']*5 + ['packets', 'bytes', 'flows', 'unique src ip', 'distinct flows', 'unique src port', 'unique dst port', 'unique pkt size']
    #masks = [5, 6, 7, 8]
    

    options = ['sa', 'da', 'sp', 'dp', 'packet size', 'total pkts', 'total bytes', 'total flows']
    legends = ['source address', 'destination address', 'source port', 'destination port', 'flow packet size', 'total pkts', 'total bytes', 'total flows']
    ylabels = ['entropy']*5 + ['packets', 'bytes', 'flows']
    masks = [4]

    sol.set_options(options)
    sol.set_legends(legends)
    sol.set_ylabels(ylabels)
    sol.set_masks(masks)
    sol.read_data() 
    sol.plot() 
         
if __name__ == "__main__":
    main()        
                 
    
