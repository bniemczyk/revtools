#!/usr/bin/env python
from directed import *
from algorithms import *
import algorithms
import directed
import memoize
#import fuzzy

try:
    from callgraph import *
    from functiongraph import *
    from prioritize import *
    
    import objects
    import decrypt
    import resources
    import malware
    import callgraph
    import functiongraph
    import prioritize
except:
    pass

def fixup_imports(import_dic):
  idc.Wait()

  heads = set(idautils.Heads())

  for h in heads:
    if idc.isCode(h):
      continue

    addr = idc.Dword(h)
    if addr not in import_dic:
      continue

    print 'fixing up %s at 0x%x' % (import_dic[addr], h)
    idc.MakeName(h, import_dic[addr])

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
                prioritize()
                print 'locating recursive functions'
                cg = CallGraph()
                cg.tag_recursive()
                print 'analyzing loops'
                FunctionGraph.analyze_loops()
                print 'locating signed arithmetic'
                FunctionGraph.tag_signed()

