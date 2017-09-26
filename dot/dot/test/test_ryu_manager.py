from ryu.lib import hub
import logging

LOG = logging.getLogger('dot.lib.hub') 

from ryu.base import app_manager
from ryu.controller.handler import set_ev_cls

class Test(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(Test, self).__init__(*args, **kwargs)

    def start(self):
        hub.spawn(self.hello)

    def hello(self):
        LOG.info('hello')
