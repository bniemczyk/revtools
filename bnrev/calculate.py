#!/usr/bin/env python

import distorm3
import symbolic
import copy
import memoize
import algorithms
from memoize import Memoize
from functiongraph import FunctionGraph

from idafun import *

# registers
eax,ebx,ecx,edx,esi,edi,ebp,esp = symbolic.symbols('eax ebx ecx edx esi edi ebp esp')
ax,bx,cx,dx,si,di,bp,sp = symbolic.symbols('ax bx cx dx si di bp sp')
al,ah,bl,bh,cl,ch,dl,dh = symbolic.symbols('al ah bl bh cl ch dl dh')

# functions
DEREF = symbolic.symbols('DEREF')
PHI = symbolic.symbols('PHI', associative=True, commutative=True)
AT = symbolic.symbols('@')
CALL = symbolic.symbols('CALL')
LOOKUP = symbolic.symbols('=>')

regmasks = \
    {
    ax: eax & 0xffff,
    bx: ebx & 0xffff,
    cx: ecx & 0xffff,
    dx: edx & 0xffff,
    si: esi & 0xffff,
    di: edi & 0xffff,
    bp: ebp & 0xffff,
    sp: esp & 0xffff,

    al: eax & 0xff,
    ah: eax & 0xff00,
    bl: ebx & 0xff,
    bh: ebx & 0xff00,
    cl: ecx & 0xff,
    ch: ecx & 0xff00,
    dl: edx & 0xff,
    dh: edx & 0xff00
    }

def _invert_mask(mask):
  return 0xffffffff ^ mask

def resolve_op(ist, opnum):
  op = ist.operands[opnum]

  if op.type == 'AbsoluteMemory':
    rv = 0   
    idaist = idautils.DecodeInstruction(ist.address)

    if op.index != None:
      rv += symbolic.symbols(distorm3.Registers[op.index].lower()) * op.scale
    if op.base != None:
      rv += symbolic.symbols(distorm3.Registers[op.base].lower())
    if op.disp != None:
      rv += op.disp
    return DEREF(op.op_size, rv) if ist.mnemonic.lower() != 'lea' else rv

  elif op.type == 'Register':
    return symbolic.symbols(distorm3.Registers[op.index].lower())

  elif op.type == 'Immediate':
    return symbolic.symbolic(op.value)

  elif op.type == 'AbsoluteMemoryAddress':
    return DEREF(op.op_size, op.disp)

  else:
    raise BaseException("Unknown Operand Type %s" % (op.type))

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

    def _replace(exp):
      while exp in known and known[exp] != exp:
        exp = known[exp]
      return exp

    if addr not in loop_headers:
      for i in graph.nodes[addr].incoming:
        results = calc(i, graph)
        known = _combine_dicts(known, results)

    ist = decode(addr)

    def _cleanup_derefs(exp):
      if exp[0].name == '&' and exp[2][0] == DEREF:
        if exp[1] == symbolic.symbolic(0xff) and exp[2][1] == symbolic.symbolic(0x1):
          return exp[2]
        if exp[1] == symbolic.symbolic(0xffff) and exp[2][1] == symbolic.symbolic(0x2):
          return exp[2]
        if exp[1] == symbolic.symbolic(0xffffffff) and exp[2][1] == symbolic.symbolic(0x4):
          return exp[2]

      return exp

    def _set(dst, src, extend=False):

      if dst[0] == DEREF:
        dst = dst.substitute(known)

      if src in regmasks:
        mask = regmasks[src][1]
        src = regmasks[src][2]
        src = (src & mask).substitute(known)
      else:
        src = src.substitute(known)

      if dst in regmasks:
        mask = regmasks[dst][1]
        dst = regmasks[dst][2]
        mask = _invert_mask(mask)
        known[dst] = ((dst & mask) | src).walk(_cleanup_derefs)

      else:
        known[dst] = src.walk(_cleanup_derefs)

    def _dstsrc(istn, fnc, extend=False):
      if ist.mnemonic.lower() == istn:
        dst,src = _resolve_ops(ist, 2)
        _set(dst, fnc(dst, src), extend=extend)

    def _oneop(istn, fnc):
      if ist.mnemonic.lower() == istn:
        x = _resolve_ops(ist, 1)
        _set(x, fnc(x))

    # arithmetic
    _dstsrc('add', lambda dst, src: dst + src)
    _dstsrc('sub', lambda dst, src: dst - src)
    _dstsrc('mul', lambda dst, src: dst * src)
    _dstsrc('div', lambda dst, src: dst / src)
    _dstsrc('xor', lambda dst, src: dst ^ src)
    _dstsrc('or', lambda dst, src: dst | src)
    _dstsrc('and', lambda dst, src: dst & src)
    _oneop('inc', lambda x: x + 1)
    _oneop('dec', lambda x: x - 1)

    # mov instructions
    _dstsrc('lea', lambda dst, src: src) # resolve_op is smart enough to not DEREF lea's
    _dstsrc('mov', lambda dst, src: src)
    _dstsrc('movsx', lambda dst, src: src, extend=True)
    _dstsrc('movzx', lambda dst, src: src, extend=True)

    # stack manipulations instructions
    def _stack(istn, offset, dst=None, src=None):
      if ist.mnemonic.lower() == istn:
        pesp = esp if esp not in known else known[esp]

        if src != None:
          known[DEREF(ist.operands[0].op_size, pesp+offset)] = src().substitute(known).walk(_cleanup_derefs)

        if dst != None:
          known[dst] = DEREF(ist.operands[0].op_size, pesp)

        known[esp] = pesp+offset

    _stack('push', -4, src=lambda: _resolve_ops(ist, 1))
    _stack('pop', 4, dst=lambda: _resolve_ops(ist, 1))

    # function calls
    if ist.mnemonic.lower() == 'call': 
      fn = _resolve_ops(ist, 1)
      if isinstance(fn, symbolic.Number):
        fn_name = idc.GetFunctionName(int(fn.n))
        if fn_name != '':
          fn = fn_name


      known[eax] = LOOKUP(AT(CALL(fn), ist.address), eax)
      known[ecx] = LOOKUP(AT(CALL(fn), ist.address), ecx)
      known[edx] = LOOKUP(AT(CALL(fn), ist.address), edx)
      known[esp] = known[esp] + idc.GetSpDiff(ist.address+ist.size)

    return known
