#!/usr/bin/env python

import sympy
from directed import DirectedGraph

class Noun(str):
    
    def __new__(cls, name):
        self = str.__new__(cls, name)
        self.name = name
        return self

    def describe(self, adj):
        return Modifier(adj, self)

class Modifier(tuple):
    
    def __new__(cls, name, inner):
        self = tuple.__new__(cls, (name, inner))
        self.name = name
        self.inner = inner

        return self

    def describe(self, adv):
        return Modifier(adv, self)

    def __repr__(self):
        return '%s %s' % (self.name, self.inner)

class Fuzzy(object):
    def __init__(self):
        self.graph = DirectedGraph()

if __name__ == '__main__':
    testnoun = Noun('number')
    print testnoun.describe('real')
