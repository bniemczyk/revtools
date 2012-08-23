#!/usr/bin/env python
from collections import deque
import copy

class DirectedGraph(object):
    class Node(object):
        def __init__(self, value):
            self.outgoing = set()
            self.incoming = set()
            self.value = value

    def copy():
        return copy.deepcopy(self)

    def __init__(self):
        self.nodes = {}

    def connect(self, src, dst):
        if src not in self.nodes:
            self.nodes[src] = DirectedGraph.Node(src)
        if dst not in self.nodes:
            self.nodes[dst] = DirectedGraph.Node(dst)

        self.nodes[src].outgoing.add(dst)
        self.nodes[dst].incoming.add(src)

    def walk(self, src, direction='outgoing'):
        src = self.nodes.setdefault(src, DirectedGraph.Node(src))
        q = deque([(src,0)])
        seen = set([src.value])

        while len(q) > 0:
            node,level = q.popleft()
            yield (node.value,level)
            seen.add(node.value)
            for i in (node.outgoing if direction == 'outgoing' else node.incoming):
                if i in seen:
                    continue
                else:
                    q.append((self.nodes[i],level+1))

    def adjacency_matrix(self):
        import numpy
        ids = {}
        nid = 0
        for i in self.nodes.values():
            ids[i.value] = nid
            nid += 1

        m = numpy.zeros((nid,nid), dtype=numpy.int)
        for i in self.nodes.values():
            for j in i.outgoing:
                m[ids[i.value],ids[j]] = numpy.int(1)

        rids = {}
        for k in ids:
            rids[ids[k]] = k

        return (rids, numpy.matrix(m))

if __name__ == '__main__':
    from algorithms import *

    dg = DirectedGraph()
    dg.connect('a', 'b')
    dg.connect('b', 'c')
    dg.connect('b', 'd')
    dg.connect('d', 'a')

    print graph_string(dg)

    for node,level in dg.walk('a'):
        print "%s level[%d]" % (node,level)

    cylic = list(find_cylic_nodes(dg))
    print 'cyclic nodes: %s' % (cylic)
