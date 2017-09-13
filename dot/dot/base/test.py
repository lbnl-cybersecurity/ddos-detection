import itertools

app_lists = ['1', '2', '3', '4']
app_lists = [app for app in itertools.chain.from_iterable(app.split(',') for app in app_lists)]
print app_lists

a = 'a'
assert a!='a'
print 'b'
