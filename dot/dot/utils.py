# Reference
# https://github.com/osrg/ryu/blob/master/ryu/utils.py
#
import importlib
import logging

LOG = logging.getLogger('dot.utils')

def import_module(modname):
    # Import module with python module path
    # e.g.) modname = 'module.path.module_name'
    return importlib.import_module(modname)
