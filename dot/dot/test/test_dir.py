def func(a):
    print a

print dir(func)
print callable(func)

class Test(object):
    def __init__(self):
        super(Test, self).__init__

print Test.__module__
sol = Test()
print sol.__class__
print "Module", sol.__class__.__module__
print "Name", sol.__class__.__name__
