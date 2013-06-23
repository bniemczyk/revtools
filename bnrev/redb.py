#!/usr/bin/env python
import redis

_redis_types = {
    type(1): 'int',
    type(1.0): 'float',
    type({}): 'dict',
    type('str'): 'str'
}

def _get_redis_type(obj):
    if type(obj) in _redis_types:
        return _redis_types[type(obj)]
    else:
        return 'object'
