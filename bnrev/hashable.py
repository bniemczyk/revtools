#!/usr/bin/env python

from copy import copy,deepcopy

class HashableDict(dict):

  def __hash__(self, seen=None):
    return 0

  def __eq__(self, other):
    if other == None:
      return False
    if type(other) != type(self):
      return False

    for k in self:
      if k not in other or other[k] != self[k]:
        return False

    for k in other:
      if k not in self or other[k] != self[k]:
        return False

    return True

  def copy(self):
    return copy(self)
