# Reference
# https://github.com/osrg/ryu/blob/master/ryu/controller/handler.py
#
import sys
import inspect
import logging

LOG = logging.getLogger('dot.controller.handler')

class _Caller(object):
    """
    Describe how to handle an event class.
    """
    def __init__(self, ev_source):
        """
        :param ev_source: The module which generates the event.
        ev_cls.__module__ for set_ev_cls.
        None for set_ev_handler.
        """
        self.ev_source = ev_source

def _listify(may_list):
    if may_list is None:
        may_list = []
    if not isinstance(may_list, list):
        may_list = [may_list]
    return may_list

def set_ev_cls(ev_cls):
    """
    A decorator for DDoS detection application to declare an event handler.

    Decorated method will become an event handler.
    :param ev_cls: An event class whose instances this application wants to receive.
    """
    def _set_ev_cls(handler):
        if 'callers' not in dir(handler):
            handler.callers = {}
        for e in _listify(ev_cls):
            handler.callers[e] = _Caller(e.__module__)
        return handler
    return _set_ev_cls

def _has_caller(method):
    return hasattr(method, 'callers')

def register_instance(i):
    for _k, m in inspect.getmembers(i, inspect.ismethod):
        LOG.debug('instance %s k %s m %s', i, _k, m)
        if _has_caller(m):
            for ev_cls, c in m.callers.items():
                i.register_handler(ev_cls, m)

def register_service(service):
    """
    Register the detection application specified by 'service' as 
    a provider of events defined in the calling module.

    If an application being loaded consumes events (in the sense of 
    set_ev_cls) provided by the "service" application, the latter 
    application will be automatically loaded.

    This mechanism is used to e.g. automatically start controller if 
    there are applications consuming NEW-FILE events.
    """
    frame = inspect.currentframe()
    m_name = frame.f_back.f_globals['__name__']
    m = sys.modules[m_name]
    m._SERVICE_NAME = service
