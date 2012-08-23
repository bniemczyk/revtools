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

if __name__ == '__main__':
    dg = DirectedGraph()
    dg.connect('a', 'b')
    dg.connect('b', 'c')
    dg.connect('b', 'd')
    dg.connect('b', 'a')

    for node,level in dg.walk('a'):
        print "%s level[%d]" % (node,level)
