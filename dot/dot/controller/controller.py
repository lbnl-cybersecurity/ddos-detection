# Controller application module
import pyinotify
import logging

from dot.base import app_manager
from dot import cfg
from dot.controller import nf_event
from dot.lib import hub

LOG = logging.getLogger('controller')
CONF = cfg.CONF
CONF.register_cli_opts([
    cfg.StrOpt('work-dir', default=None, help='working directory'),
    ])

class Controller(app_manager.DotApp):
    _EVENTS = {nf_event.NewFileEvent}

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)

    def start(self):
        super(Controller, self).start()
        return hub.spawn(self.monitor_working_dir, CONF.work_dir)

    def monitor_working_dir(self, working_dir):
        # Watch manager
        wm = pyinotify.WatchManager()
        wm.add_watch(working_dir, pyinotify.IN_CLOSE_WRITE, rec=True)
        
        # Notifier
        notifier = pyinotify.Notifier(wm, self.find_new_file)
        notifier.loop()

    def find_new_file(self, event):
        print "CLOSE_WRITE event: ", event.pathname
