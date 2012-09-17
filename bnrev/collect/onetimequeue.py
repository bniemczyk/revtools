#!/usr/bin/env python
from collections import deque

class onetimequeue(deque):
    def __init__(self):
        self._seen = set()
        super(onetimequeue, self).__init__()

    def append(self, value, key=None):
        if key == None:
            key = value

        if key not in self._seen:
            self._seen.add(key)
            return super(onetimequeue, self).append(value)
        else:
            return None

    def appendleft(self, value, key=None):
        if key == None:
            key = value

        if key not in self._seen:
            self._seen.add(key)
            return super(onetimequeue, self).appendleft(value)
        else:
            return None
