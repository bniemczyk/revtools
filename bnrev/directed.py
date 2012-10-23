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

    def clear():
        self.nodes = {}

    def copy():
        return copy.deepcopy(self)

    def __init__(self):
        self.nodes = {}
        self.exit_nodes = set()
        self.edges = {}
        self.metadata = {}

    def add_node(self, node):
        self.nodes.setdefault(node, DirectedGraph.Node(node))

    def connect(self, src, dst, edgeValue=None):
        if src not in self.nodes:
            self.nodes[src] = DirectedGraph.Node(src)
        if dst not in self.nodes:
            self.nodes[dst] = DirectedGraph.Node(dst)

        self.nodes[src].outgoing.add(dst)
        self.nodes[dst].incoming.add(src)

        if edgeValue != None:
            self.edges.setdefault((src,dst), set()).add(edgeValue)

    def strip_edges_to(self, dst):
        n = self.nodes[dst]
        for i in n.incoming:
            ni = self.nodes[i]
            ni.outgoing = filter(lambda x: x != dst, ni.outgoing)
        n.incoming = set()

    def strip_edges_from(self, src):
        n = self.nodes[src]
        for i in n.outgoing:
            ni = self.nodes[i]
            ni.incoming = filter(lambda x: x != src, ni.incoming)
        n.outgoing = set()

    def remove_node(self, n):
        self.strip_edges_to(n)
        self.strip_edges_from(n)
        del self.nodes[n]

    def __contains__(self, n):
        return n in self.nodes

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

            linked = set()
            if direction in ['either', 'outgoing']:
                linked = linked.union(node.outgoing)
            if direction in ['either', 'incoming']:
                linked = linked.union(node.incoming)

            for i in linked:
                if i in seen:
                    continue
                else:
                    seen.add(i)
                    q.append((self.nodes[i],level+1))

    def within_distance(self, src, distance, direction='outgoing'):
        for n,l in self.walk(src, direction=direction):
            if l > distance:
                break
            yield n

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
                    seen.add(i)
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
        return e - len(self.nodes) + (len(self.exit_nodes) * 2)

    def visualize(self,layout='dot'):
        import pydot
        import tempfile
        import os
        dotg = pydot.Dot('tmp', graph_type='digraph')

        dotnodes = {}
        for n in self.nodes:
            dotnodes[n] = pydot.Node(str(n))
            dotg.add_node(dotnodes[n])

        for n in self.nodes:
            for o in self.nodes[n].outgoing:
                if (n, o) in self.edges:
                    for e in self.edges[(n,o)]:
                        dotg.add_edge(pydot.Edge(dotnodes[n], dotnodes[o],label=e))
                else:
                    dotg.add_edge(pydot.Edge(dotnodes[n], dotnodes[o]))

        f = tempfile.NamedTemporaryFile(mode='w+b',delete=False)

        try:
            f.write(dotg.to_string())
            f.close()
            os.system('cat %s' % (f.name,))
            os.system('xdot --filter=%s %s' % (layout, f.name))
        finally:
            os.unlink(f.name)

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

    cylic = list(find_cylic_nodes(dg, 'a'))
    print 'cyclic nodes: %s' % (cylic)

    print 'domination set: %s' % (dominate_sets(dg, 'a'),)
    print 'domination tree: %s' % (graph_string(domtree(dominate_sets(dg, 'a'))))
    print 'loop headers: %s' % (loop_headers(dg, dominate_sets(dg, 'a'), 'a'))
