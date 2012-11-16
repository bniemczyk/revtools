#!/usr/bin/env python

import symbolic
import copy
import memoize
import algorithms
from memoize import Memoize
from functiongraph import FunctionGraph

from idafun import *

eax,ebx,ecx,edx,esi,edi,ebp,esp = symbolic.symbols('eax ebx ecx edx esi edi ebp esp')
DEREF = symbolic.symbols('DEREF')
PHI = symbolic.symbols('PHI', associative=True, commutative=True)

def resolve_op(ist, opnum):
  o = ist[opnum]
  os = op_size(o)

  if o.type == idaapi.o_reg:
    return symbolic.symbols(idaapi.get_reg_name(o.reg, 4))

  if o.type == idaapi.o_imm:
    return symbolic.symbolic(o.value)

  if o.type in set([idaapi.o_displ, idaapi.o_phrase]):
    rv = symbolic.symbols(idaapi.get_reg_name(o.phrase, 4))
    #FIXME: does not handle [reg+reg*mult+offset]
    #if o.specflag1 != 0:
    #  rv = rv + symbolic.symbols(idaapi.get_reg_name(o.specflag2, 4))
    rv = rv + (o.addr if o.addr < 2**31 else -(2**32 - o.addr))
    if ist.itype != idaapi.NN_lea:
      rv = DEREF(rv)
    return rv

  if o.type in set([idaapi.o_near, idaapi.o_far]):
    return symbolic.symbolic(o.addr)

def phi(src1, src2):
  if src1 == src2:
    return src1
  return PHI(src1, src2)

def _is_deref(arg):
  return isinstance(arg, symbolic.Fn) and arg.fn == DEREF

def _combine_dicts(a, b):
  rv = copy.copy(a)

  for k in b:
    if k not in rv:
      rv[k] = b[k]
    else:
      rv[k] = phi(rv[k], b[k])

  return rv

def calc(addr=None, graph=None):
  '''
  calc known values at addr, assuming a blank slate at the top of the loop or function
  '''

  if addr == None:
    addr = idc.ScreenEA()

  if graph == None:
    graph = FunctionGraph(addr)

  def _resolve_ops(ist, n):
    rv = []
    for i in range(n):
      rv.append(resolve_op(ist, i))
    return tuple(rv) if n > 1 else rv[0]

  with memoize.m(algorithms, 'dominate_sets'):
    ds = algorithms.dominate_sets(graph, graph.start_addr)
    loop_headers = algorithms.loop_headers(graph, ds, graph.start_addr)
    known = {}

    if addr not in loop_headers:
      for i in graph.nodes[addr].incoming:
        results = calc(i, graph)
        known = _combine_dicts(known, results)

    ist = idautils.DecodeInstruction(addr)

    def _dstsrc(istn, fnc):
      if ist.itype == istn:
        dst,src = _resolve_ops(ist, 2)
        if _is_deref(dst):
          dst = dst.substitute(known)
        known[dst] = fnc(dst.substitute(known), src.substitute(known))

    # arithmetic
    _dstsrc(idaapi.NN_add, lambda dst, src: dst + src)
    _dstsrc(idaapi.NN_sub, lambda dst, src: dst - src)
    _dstsrc(idaapi.NN_mul, lambda dst, src: dst * src)
    _dstsrc(idaapi.NN_div, lambda dst, src: dst / src)
    _dstsrc(idaapi.NN_xor, lambda dst, src: dst ^ src)
    _dstsrc(idaapi.NN_or, lambda dst, src: dst | src)
    _dstsrc(idaapi.NN_and, lambda dst, src: dst & src)

    # mov instructions
    _dstsrc(idaapi.NN_lea, lambda dst, src: src) # resolve_op is smart enough to not DEREF lea's
    _dstsrc(idaapi.NN_mov, lambda dst, src: src)
    _dstsrc(idaapi.NN_movsx, lambda dst, src: src)
    _dstsrc(idaapi.NN_movzx, lambda dst, src: src)

    # stack manipulations instructions
    def _stack(istn, offset, dst=None, src=None):
      if ist.itype == istn:
        pesp = esp.substitute(known)
        known[esp] = (pesp + offset).substitute(known)

        if src != None:
          known[DEREF(pesp+offset)] = src().substitute(known)

    _stack(idaapi.NN_push, -4, src=lambda: _resolve_ops(ist, 1))
    _stack(idaapi.NN_pop, 4, dst=lambda: _resolve_ops(ist, 1))

    return known
