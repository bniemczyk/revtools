#!/usr/bin/env python

class HashableDict(dict):

  def __hash__(self, seen=None):
    return 0

  def __eq__(self, other):
    for k in self:
      if k not in other or other[k] != self[k]:
        return False

    for k in other:
      if k not in self or other[k] != self[k]:
        return False

    return True
