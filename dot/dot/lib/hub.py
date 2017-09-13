# Reference
# https://github.com/osrg/ryu/blob/master/ryu/lib/hub.py

import logging
import os

LOG = logging.getLogger('dot.lib.hub')
HUB_TYPE = 'eventlet'

if HUB_TYPE == 'eventlet':
    import eventlet
    import eventlet.event
    import eventlet.queue
    import traceback

    def spawn(*args, **kwargs):
        raise_error = kwargs.pop('raise_error', False)

        def _launch(func, *args, **kwargs):
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

