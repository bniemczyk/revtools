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

