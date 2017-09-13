"""
The central management of DDoS detection applications.

- Load DDoS detection applications.
- Route messages among detection applications.
"""
# Reference
# https://github.com/osrg/ryu/tree/master/ryu/base
#
import logging
import itertools
import inspect

from dot import utils
from dot.controller.handler import register_instance

LOG = logging.getLogger('dot.base.app_manager')
SERVICE_BRICKS = {}

def register_app(app):
    assert isinstance(app, DotApp)
    assert app.name not in SERVICE_BRICKS
    SERVICE_BRICKS[app.name] = app
    # In this step, the app itself learns what event classes
    # itself will listen to, and what handlers within itself 
    # are handling these event classes.
    register_instance(app)

def unregister_app(app):
    SERVICE_BRICKS.pop(app.name)

class DotApp(object):
    """
    The base class for DDoS detection applications.
    DotApp subclasses are instantiated after app-manager loaded
    all requested application modules.
    __init__ should call DotApp.__init__ with the same arguments.
    It's illegal to send any events in __init__.

    The instance attribute 'name' is the name of the class used 
    for message routing among DDos detection applications.
    It's set to __class__.__name__ by DotApp.__init__.
    It's discouraged for subclasses to override this.

    """
    _EVENTS = []
    """
    A list of event classes which this DotApp subclass would generate.
    This should be specified if and only if event classes are defined in 
    a different python module from the DotApp sublcass is. 

    However, in our framework, 
    you should always use  _EVENTS to specify event classes that this 
    DotApp subclass would generate.
    """

    def __init__(self, *_args, **_kwargs):
        super(DotApp, self).__init__()
        self.name = self.__class__.__name__
        #key:ev_cls, value:a list of handlers (methods)
        self.event_handlers = {}
        #key:ev_cls, value:a list of observers (app.name)
        self.event_observers = {}

    def start(self):
        pass

    def register_handler(self, ev_cls, handler):
        assert callable(handler)
        self.event_handlers.setdefault(ev_cls, [])
        self.event_handlers[ev_cls].append(handler)

    def unregister_handler(self, ev_cls, handler):
        assert callable(handler)
        self.event_handlers[ev_cls].remove(handler)
        if not self.event_handlers[ev_cls]:
            del self.event_handlers[ev_cls]

    def register_observer(self, ev_cls, name):
        ev_cls_observers = self.event_observers.setdefault(ev_cls, set())
        ev_cls_observers.add(name)

    def unregister_observer(self, ev_cls, name):
        self.event_observers[ev_cls].remove(name)


class AppManager(object):
    # singleton
    _instance = None

    @staticmethod
    def get_instance():
        if not AppManager._instance:
            AppManager._instance = AppManager()
        return AppManager._instance

    def __init__(self):
        # key: app_cls_name, value: app_cls
        self.applications_cls = {}
        # key: app_name, value: app_cls object
        self.applications = {}
    
    def load_app(self, name):
        mod = utils.import_module(name)
        clses = inspect.getmembers(mod, lambda cls:(inspect.isclass(cls) and 
                                        issubclass(cls, DotApp) and 
                                        mod.__name__ == cls.__module__))
        if clses:
            return clses[0][1]
        return None

    def load_apps(self, app_lists):
        app_lists = [app for app in itertools.chain.from_iterable(app.split(',') for app in app_lists)]

        while len(app_lists)>0:
            app_cls_name = app_lists.pop(0)

            LOG.info('loading app %s', app_cls_name)

            cls = self.load_app(app_cls_name)
            if cls is None:
                continue
            self.applications_cls[app_cls_name] = cls
    
    def _update_bricks(self):
        for i in SERVICE_BRICKS.values():
            for _k, m in inspect.getmembers(i, inspect.ismethod):
                if not hasattr(m, 'callers'):
                    continue
                for ev_cls, c in m.callers.items():
                    for brick in SERVICE_BRICKS.values():
                        if ev_cls in brick._EVENTS:
                            brick.register_observer(ev_cls, i.name)

    @staticmethod
    def _report_brick(name, app):
        LOG.debug("BRICK %s", name)
        for ev_cls, list_ in app.event_observers.items():
            LOG.debug(" PROVIDES %s TO %s", ev_cls.__name__, list_)
        for ev_cls in app.event_handlers.keys():
            LOG.debug(" CONSUMES %s", ev_cls.__name__)

    @staticmethod
    def report_bricks():
        for brick, i in SERVICE_BRICKS.items():
            AppManager._report_brick(brick, i)

    def _instantiate(self, app_cls_name, cls, *args, **kwargs):
        # For now, only a single instance of a given module is instantiated.
        LOG.info('instantiating app %s of %s', cls.__name__, app_cls_name)
        if app_cls_name is not None:
            assert app_cls_name not in self.applications
        app = cls(*args, **kwargs)
        register_app(app)
        assert app.name not in self.applications
        self.applications[app.name] = app
        return app

    def instantiate_apps(self, *args, **kwargs):
        for app_cls_name, cls in self.applications_cls.items():
            self._instantiate(app_cls_name, cls, *args, **kwargs)
        
        # In this step, the applications that generate events will
        # learn what other applications are listening to the events they 
        # are generating. This is the critical step in routing messages 
        # between different applications.
        self._update_bricks()
        self.report_bricks()
