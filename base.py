import time

class Base(object):
    pattern = '%Y-%m-%d %H:%M:%S'   # date time format
    
    def __init__(self):
        pass

    @classmethod
    def epoch(cls, date_time):
        ### convert time string to epoch time
        try:
            epoch = int(time.mktime(time.strptime(date_time, cls.pattern)))
            return epoch
        except Exception as e:
            print "Error: ", str(e)


