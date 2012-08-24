#!/usr/bin/env python

def find_cylic_nodes(graph):
    nmap, m = graph.adjacency_matrix()
    for i in range(len(m)):
        m[i,i] += 1
    m = m ** len(m)
    for i in range(len(m)):
        if m[i,i] > 1:
            yield nmap[i]

def graph_string(graph):
    rv = []
    nmap, m = graph.adjacency_matrix()
    for i in range(len(m)):
        for j in range(len(m)):
            if m[i,j] > 0:
                rv.append('%s -> %s' % (nmap[i], nmap[j]))
    return ', '.join(rv)

# returns a the popularity of a node, or all nodes if node=None, the popularity of a node
# is defined as the count of nodes that have a path to reach said node excluding itself
def popularity(graph, node=None):
    if node != None:
        pop = 0
        for n,l in graph.walk(node, direction='incoming'):
            if l > 0:
                pop += 1
        return pop
    else:
        def inner():
            for i in graph.nodes():
                yield (i, popularity(graph, i))
        return inner
