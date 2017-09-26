import inspect
from ryu import utils

def _listify(may_list):
    if may_list is None:
        may_list = []
    if not isinstance(may_list, list):
        may_list = [may_list]
    return may_list

name = 'test'
mod = utils.import_module(name)
print mod.__name__
clses = inspect.getmembers(mod, lambda cls:inspect.isclass(cls))
print clses
for cls in _listify(clses[0][1]):
    print cls.__module__
    print cls.__name__



