#!/usr/bin/env python

from sympy import symbols
from symath.graph.directed import DirectedGraph

# adjectives
low,high,medium = symbols('low high medium')

# adverb
somewhat,very = symbols('somewhat very')

fznot,fzand,fzor = symbols('fznot fzand fzor')

bidirectional = set(map(str, [low,high,medium,fznot,somewhat,very]))

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

    def add(self, prop):
        self.graph.add_node(prop)

        if prop.is_Function:
            for a in prop.args:
                self.add(a)
                self.graph.connect(a, prop)
                if str(prop.func) in bidirectional:
                    self.graph.connect(prop, a)

    def implies(self, condition, result):
        self.add(condition)
        self.add(result)
        self.graph.connect(condition, result, 'Imp')

if __name__ == '__main__':
    import bnrev.algorithms as alg
    temp,hot,cold,mild = symbols('temp hot cold mild')
    fz = Fuzzy()

    fz.implies(fzand(fznot(cold),fznot(hot)), mild)
    fz.implies(low(temp), cold)
    fz.implies(high(temp), hot)
    print alg.graph_string(fz.graph)
    fz.graph.visualize(layout='dot')
