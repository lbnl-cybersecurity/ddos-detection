import logging
import os
import time

LOG = logging.getLogger('dot.lib.hub')
HUB_TYPE = 'eventlet'

if HUB_TYPE == 'eventlet':
    import eventlet
    # HACK:
    # sleep() is the workaround for the following issue.
    # https://github.com/eventlet/eventlet/issues/401
    #eventlet.sleep()
    eventlet.monkey_patch()
    import traceback
   
    print "I am here"
    def spawn(*args, **kwargs):
        print "I am in spawn"
        raise_error = kwargs.pop('raise_error', False)

        def _launch(func, *args, **kwargs):
            print func
            # Mimic gevent's default raise_error=False behaviour
            # by not propagating an exception to the joiner.
            try:
                return func(*args, **kwargs)
            except TaskExit:
                pass
            except BaseException as e:
                if raise_error:
                    raise e
                # Log uncaught exception.
                # Note: this is an intentional divergence from gevent
                # behaviour; gevent silently ignores such exceptions.
                LOG.error('hub: uncaught exception: %s', traceback.format_exc())

        return eventlet.spawn(_launch, *args, **kwargs)


    def hello():
        LOG.info('hello')

    spawn(hello)
    time.sleep(10)    
