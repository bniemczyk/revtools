#!/usr/bin/env python
from directed import *
from algorithms import *
from callgraph import *
from functiongraph import *
from prioritize import *

import objects
import decrypt
import resources
import malware
import memoize
import directed
import algorithms
import callgraph
import functiongraph
import prioritize

def analyze():
    idc.Wait()

    with memoize.m(algorithms, 'nothing'):
        with memoize.m(functiongraph.FunctionGraph, 'nothing'):
            with memoize.m(callgraph.CallGraph, 'nothing'):
                print 'analyzing vtables'
                objects.analyze_vtables()
                print 'finding loops with xors'
                FunctionGraph.tag_xors()
                print 'prioritizing'
                prioritize.prioritize()
                print 'locating recursive functions'
                cg = callgraph.CallGraph()
                cg.tag_recursive()
                print 'analyzing loops'
                FunctionGraph.analyze_loops()
                print 'locating signed arithmetic'
                FunctionGraph.tag_signed()

