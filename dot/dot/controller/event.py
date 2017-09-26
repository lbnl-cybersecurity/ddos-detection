# Reference
# https://github.com/osrg/ryu/blob/master/ryu/controller/event.py
#
class EventBase(object):
    """
    The base of all event classes.
    
    A DDoS detection application can define its own event type by creating a subclass.
    """
    def __init__(self):
        super(EventBase, self).__init__()
