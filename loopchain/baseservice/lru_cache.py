# origin code from https://codereview.stackexchange.com/questions/166388/my-lru-cache-implementation
# and modify with https://python-3-patterns-idioms-test.readthedocs.io/en/latest/PythonDecorators.html

from collections import OrderedDict
from functools import wraps
from inspect import signature


def lru_cache(maxsize=None, not_none_returns_only=False):
    def decorator(func):
        func_sig = signature(func)
        cache = OrderedDict()

        @wraps(func)
        def decorated(*args, **kwargs):
            bind = func_sig.bind(*args, **kwargs)
            bind.apply_defaults()
            args, kwargs = bind.args, bind.kwargs
            key = (args, tuple(sorted(kwargs.items())))
            try:
                val = cache[key]
            except KeyError:
                val = func(*args, **kwargs)
                if not_none_returns_only and val is None:
                    pass
                else:
                    cache[key] = val
            if maxsize and len(cache) > maxsize:
                cache.popitem(last=False)

            return val
        return decorated
    return decorator
