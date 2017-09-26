def outter(*args, **kwargs):
    print args
    print kwargs
    def _inner(func, *args, **kwargs):
        func(*args, **kwargs)
    _inner(*args, **kwargs)

def hello():
    print "hello"

outter(hello)
