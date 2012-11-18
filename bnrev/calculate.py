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
eflags = symbolic.symbols('eflags')

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

def calc(addr=None, graph=None, _loop_headers=None, target=None):
  '''
  calc known values at addr, assuming a blank slate at the top of the loop or function
  '''

  if _loop_headers == None:
    _loop_headers = {}

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
    if graph.start_addr not in _loop_headers:
      _loop_headers[graph.start_addr] = algorithms.loop_headers(graph, ds, graph.start_addr) 
    loop_headers = _loop_headers[graph.start_addr]
    known = {}

    ist = decode(addr)

    # shortcut!!
    if target != None and \
        ist.mnemonic.lower() == 'mov' and \
        ist.operands[1].type == 'Immediate' and \
        ist.operands[0].type == 'Register' and \
        distorm3.Registers[ist.operands[0].index].lower() == target.name:
      known[target] = symbolic.symbolic(ist.operands[1].value)
      return known

    if addr not in loop_headers:
      for i in graph.nodes[addr].incoming:
        results = calc(i, graph, _loop_headers=_loop_headers, target=target)
        known = _combine_dicts(known, results)

    def _cleanup_derefs(exp):
      if exp[0].name == '&' and exp[2][0] == DEREF:
        if (exp[1] & 0xff) == symbolic.symbolic(0xff) and exp[2][1] == symbolic.symbolic(0x1):
          exp = exp[2]
        if (exp[1] & 0xffff) == symbolic.symbolic(0xffff) and exp[2][1] == symbolic.symbolic(0x2):
          exp = exp[2]
        if (exp[1] & 0xffffffff) == symbolic.symbolic(0xffffffff) and exp[2][1] == symbolic.symbolic(0x4):
          exp = exp[2]

      if exp[0] == DEREF:
        if exp in known:
          exp = known[exp]

      return exp

    def _set(dst, src, extend=False, iscmp=False, ismov=False):

      oldflags = known[eflags] if eflags in known else eflags

      if dst[0] == DEREF:
        dst = dst.substitute(known)

      if src in regmasks:
        mask = regmasks[src][1]
        src = regmasks[src][2]
        src = (src & mask).substitute(known)
      else:
        src = src.substitute(regmasks).substitute(known)

      if dst in regmasks:
        mask = regmasks[dst][1]
        dst = regmasks[dst][2]
        mask = _invert_mask(mask)
        known[eflags] = ((dst & mask) | src).walk(_cleanup_derefs)

      else:
        known[eflags] = src.walk(_cleanup_derefs)

      if not iscmp:
        known[dst] = known[eflags]

      if ismov:
        known[eflags] = oldeflags

    def _dstsrc(istn, fnc, extend=False, iscmp=False):
      if ist.mnemonic.lower() == istn:
        dst,src = _resolve_ops(ist, 2)
        _set(dst, fnc(dst, src), extend=extend, iscmp=iscmp)

    def _oneop(istn, fnc, iscmp=False):
      if ist.mnemonic.lower() == istn:
        x = _resolve_ops(ist, 1)
        _set(x, fnc(x), iscmp=iscmp)

    # arithmetic
    _dstsrc('add', lambda dst, src: dst + src)
    _dstsrc('sub', lambda dst, src: dst - src)
    _dstsrc('cmp', lambda dst, src: dst - src, iscmp=True)
    _dstsrc('mul', lambda dst, src: dst * src)
    _dstsrc('div', lambda dst, src: dst / src)
    _dstsrc('xor', lambda dst, src: dst ^ src)
    _dstsrc('or', lambda dst, src: dst | src)
    _dstsrc('and', lambda dst, src: dst & src)
    _dstsrc('test', lambda dst, src: dst & src, iscmp=True)
    _dstsrc('sar', lambda dst, src: dst >> src)
    _dstsrc('shr', lambda dst, src: dst >> src)
    _dstsrc('sal', lambda dst, src: dst << src)
    _dstsrc('shl', lambda dst, src: dst << src)
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
          known[dst()] = DEREF(ist.operands[0].op_size, pesp).walk(_cleanup_derefs)

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
      known[esp] = known[esp] + idc.GetSpDiff(ist.address+ist.size) if esp in known else esp + idc.GetSpDiff(ist.address+ist.size)

    return known
