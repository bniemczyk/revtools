#!/usr/bin/env python
from collections import deque
import copy

# it may be simpler to represent these as an adjacency matrix directly, but i plan
# on using some big ass graphs, so we save some memory by doing it this way
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

    def add_node(self, node):
        self.nodes.setdefault(node, DirectedGraph.Node(node))

    def connect(self, src, dst):
        if src not in self.nodes:
            self.nodes[src] = DirectedGraph.Node(src)
        if dst not in self.nodes:
            self.nodes[dst] = DirectedGraph.Node(dst)

        self.nodes[src].outgoing.add(dst)
        self.nodes[dst].incoming.add(src)

    def connectedQ(self, src, dst):
        src = self.nodes[src]
        for i in src.outgoing:
            if i == dst:
                return True
        return False

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

    def stackwalk(self, src, direction='outgoing'):
        src = self.nodes.setdefault(src, DirectedGraph.Node(src))
        q = deque([[src.value]])
        seen = set([src.value])

        while len(q) > 0:
            stack = q.popleft()
            yield stack
            seen.add(stack[-1])
            n = self.nodes[stack[-1]]
            for i in (n.outgoing if direction == 'outgoing' else n.incoming):
                if i in seen:
                    continue
                else:
                    newstack = copy.copy(stack)
                    newstack.append(i)
                    q.append(newstack)

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

    def _edge_count(self):
        ec = 0
        for n in self.nodes:
            ec += len(self.nodes[n].outgoing)
        return ec

    def cyclomatic_complexity(self):
        e = self._edge_count()
        return e - len(self.nodes) + 2

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

    for stack in dg.stackwalk('a'):
        print stack

    cylic = list(find_cylic_nodes(dg))
    print 'cyclic nodes: %s' % (cylic)
