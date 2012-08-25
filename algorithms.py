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

def walk(graph, src, direction='outgoing'):
    if hasattr(graph, 'walk'):
        return graph.walk(src, direction)
    raise "Unimplemented"

def walk_edges(graph, src, direction='outgoing'):
    from collections import deque
    nmap, m = graph.adjacency_matrix()
    found = False
    for i in nmap:
        if nmap[i] == src:
            src = i
            found = True
            break

    if not found:
        raise "Invalid src node"

    seen = set()
    q = deque([src])

    while len(q) > 0:
        src = q.popleft()
        seen.add(src)
        for i in len(m):
            if m[src,i] > 0:
                yield (nmap[src], nmap[i])
                if i not in seen:
                    seen.add(i)
                    q.append(i)

def childgraph(graph, src, direction='outgoing'):
    import copy
    rv = copy.deepcopy(graph)
    rv.clear()

    for (a,b) in walk_edges(graph,src,direction=direction):
        rv.connect(a,b)

    return rv

def pathQ(graph, src, dst):
    for n,l in walk(graph, src, direction='outgoing'):
        if n == dst:
            return True
    return False

def intersect(a, b):
    ''' returns the intersection of 2 graphs'''
    import copy
    rv = copy.deepcopy(a)
    for n in a.nodes:
        if n not in b:
            rv.remove_node(n)

# returns a the popularity of a node, or all nodes if node=None, the popularity of a node
# is defined as the count of nodes that have a path to reach said node excluding itself
def popularity(graph, node=None, context=None):
    if node != None:
        pop = 0
        for n,l in graph.walk(node, direction='incoming'):
            if context == None or n in context:
                pop += 1
        return pop
    else:
        def inner():
            for i in graph.nodes():
                yield (i, popularity(graph, node=i, context=context))
        return inner
