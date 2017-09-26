# Reference
# https://github.com/osrg/ryu/blob/master/ryu/log.py
#
import logging
import sys

from dot import cfg

CONF = cfg.CONF
CONF.register_cli_opts([
    cfg.IntOpt('default-log-level', default=None, help='default log level'),
    cfg.BoolOpt('verbose', default=False, help='show debug output'),
    ])


_EARLY_LOG_HANDLER = None
def early_init_log(level=None):
    global _EARLY_LOG_HANDLER
    _EARLY_LOG_HANDLER = logging.StreamHandler(sys.stderr)

    log = logging.getLogger()
    log.addHandler(_EARLY_LOG_HANDLER)
    if level is not None:
        log.setLevel(level)

def init_log():
    log  = logging.getLogger()

    if CONF.default_log_level is not None:
        log.setLevel(CONF.default_log_level)
    elif CONF.verbose:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)

