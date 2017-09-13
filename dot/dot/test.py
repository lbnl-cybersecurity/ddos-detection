# Test Application Module
from dot.base import app_manager
from dot.controller.handler import set_ev_cls
from dot.controller import nf_event

class Test(app_manager.DotApp):
    def __init__(self, *args, **kwargs):
        super(Test, self).__init__(*args, **kwargs)

    @set_ev_cls(nf_event.NewFileEvent)
    def event_handler(self, ev):
        print ev.msg
