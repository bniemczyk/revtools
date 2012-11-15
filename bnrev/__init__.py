#!/usr/bin/env python
from directed import *
from algorithms import *
import algorithms
import directed
import memoize
import symbolic

from symbolic import symbols, symbolic, wilds, Number
Number.IFORMAT = hex

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

def make_dwords(start,end):
  for i in range(start,end,4):
    idc.MakeUnkn(i, 0)
    idc.MakeUnkn(i+1, 0)
    idc.MakeUnkn(i+2, 0)
    idc.MakeUnkn(i+3, 0)
    idc.MakeDword(i)

def fixup_imports(import_dic):
  if type(import_dic) == type('somefilename.csv'):
    lines = open(import_dic).readlines()
    import_dic = {}
    for l in lines:
      ls = l.split(',')
      addr = int(ls[0], 16)
      name = ls[1][:-1]
      import_dic[addr] = name

  idc.Wait()
  heads = set(idautils.Heads())

  for h in heads:
    if idc.isCode(h):
      continue

    addr = idc.Dword(h)
    if addr not in import_dic:
      continue

    oldh = idc.LocByName(import_dic[addr])
    if oldh != idc.BADADDR:
      idc.MakeNameEx(oldh, 'nofixup_' + import_dic[addr], idc.SN_NOCHECK|idc.SN_NOWARN)

    print 'fixing up %s at 0x%x' % (import_dic[addr], h)
    idc.MakeUnkn(h,0)
    idc.MakeUnkn(h+1,0)
    idc.MakeUnkn(h+2,0)
    idc.MakeUnkn(h+3,0)
    idc.MakeDword(h)
    idc.MakeNameEx(h, import_dic[addr], idc.SN_NOCHECK|idc.SN_NOWARN)

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

