#!/usr/bin/env python

# This is the main file to run.
# Reference
# https://github.com/osrg/ryu/blob/master/ryu/cmd/manager.py
#
import sys
import os

import logging
from dot import cfg 
from dot import log
log.early_init_log(logging.DEBUG)
from dot.controller import controller
from dot.base.app_manager import AppManager


CONF = cfg.CONF
CONF.register_cli_opts([
    cfg.MultiStrOpt('app', positional=True, default=[], 
        help='application module name to run'),
    ])


def main(args=None, prog=None):
    CONF(args=args, prog=prog)
    log.init_log()
    logger = logging.getLogger(__name__)

    app_lists = CONF.app
    # Always run controller application.
    app_lists += ['dot.controller.controller']
    print app_lists 
    app_mgr = AppManager.get_instance()
    app_mgr.load_apps(app_lists)
    services = []
    services.extend(app_mgr.instantiate_apps())
    
    #try:
    #    hub.joinall(services)
    #except KeyboardInterrupt:
    #    logger.debug("Keyboard Interrupt received. "
    #                "Closing DDoS application manager...")
    #finally:
    #    app_mgr.close()

if __name__ == "__main__":
    main()
