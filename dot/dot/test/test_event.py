# Define TestEvent subclass

from dot.controller import event

class TestEvent(event.EventBase):
    def __init__(self, msg):
        super(TestEvent, self).__init__()
        self.msg = msg
