import matplotlib.pyplot as plt

def compare_plot(y1, y2, x, xlabel, ylabel, legend, outfile):
    h = plt.figure()
    axis = h.add_subplot(1,1,1)
    axis.plot(x, y1)
    axis.plot(x, y2, '--')
    axis.set_xlabel(xlabel)
    axis.set_ylabel(ylabel)
    axis.legend(legend)
    plt.savefig(outfile)
    plt.clf()

def load_data(infile):
    data = []
    with open(infile, 'rb') as ff:
        for line in ff:
            val = float(line.rstrip('\n'))
            data.append(val)
    return data

