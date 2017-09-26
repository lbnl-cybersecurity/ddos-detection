# Test Application Module
import time
import sys

from dot.base import app_manager
from dot.lib import hub
from dot.controller.handler import set_ev_cls
from dot.controller import nf_event

class Test(app_manager.DotApp):
    def __init__(self, *args, **kwargs):
        super(Test, self).__init__(*args, **kwargs)

    def start(self):
        super(Test, self).start()
        #return hub.spawn(self.loop)
    
    def loop(self):
        i = 0
        while True:
            self.logger.info('i=%d at time %f', i, time.time())
            i += 1
            time.sleep(1)

    @set_ev_cls(nf_event.NewFileEvent)
    def event_handler(self, ev):
        self.logger.debug("Received event %s at time %f", ev.filename, time.time())
        sys.stderr.flush()        
