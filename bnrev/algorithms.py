#!/usr/bin/env python

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

def dominate_sets(graph, src):
    from collections import deque
    nodes = set(map(lambda x: x[0], walk(graph, src, direction='outgoing')))
    domset = {}
    for n in nodes:
        domset[n] = nodes

    domset[src] = set([src])
    q = deque()
    for o in graph.nodes[src].outgoing:
        q.append(o)

    while q:
        n = q.popleft()
        ds = domset[n]
        for i in graph.nodes[n].incoming:
            if i in domset:
                ds = ds.intersection(domset[i])
        ds.add(n)
        if len(ds) != len(domset[n]):
            # this nodes domination set changed, so make sure that all nodes connected to this get recalculated
            domset[n] = ds
            for o in graph.nodes[n].outgoing:
                q.append(o)

    return domset

def idom(node, domset):
    if len(domset[node]) == 1:
        return None

    ds = list(filter(lambda x: x != node, domset[node]))
    ds.sort(lambda a,b: len(domset[a]).__cmp__(len(domset[b])))
    return ds[-1]

def domtree(domset):
    import directed
    rv = directed.DirectedGraph()
    for n in domset:
        i = idom(n, domset)
        if i != None:
            rv.connect(i, n)
    return rv

def dom_frontier(graph, node, domset):
    rv = set()
    for i,_ in graph.walk(node):
        if i in domset[node]:
            continue
        for j in graph.nodes[i].incoming:
            if j in domset[node]:
                rv.add(i)
    return rv

def loop_headers(graph, domset, src):
    rv = set()
    for n,l in walk(graph, src):
        lh = graph.nodes[n].outgoing.intersection(domset[n])
        rv = rv.union(lh)
    return rv

def find_cylic_nodes(graph, src):
    ds = dominate_sets(graph, src)
    dt = domtree(ds)
    lh = loop_headers(graph, ds, src)

    cns = set()

    for h in lh:
        for n,l in walk(dt, h):
            if pathQ(graph,n,h):
                cns.add(n)

    return cns

def loop_nodes(graph, loop_head, domset):
    import copy
    # first make a copy of the graph that only contains nodes dominated by the loop header
    graph = copy.deepcopy(graph)
    for n in list(graph.nodes.keys()):
        if loop_head not in domset[n]:
            graph.remove_node(n)

    for n in list(graph.nodes.keys()):
        if pathQ(graph, n, loop_head):
            yield n
