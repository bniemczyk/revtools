#!/usr/bin/env python

#import sympy

from idafun import *

UNKNOWN_IMM = object()

def resolve_op(ist, opnum):
  o = ist[opnum]
  os = op_size(o)

  if o.type == idaapi.o_reg:
    return sympy.symbols(idaapi.get_reg_name(o.reg, 32))

  if o.type == idaapi.o_imm:
    return sympy.sympify(o.value)

  if o.type == idaapi.o_displ:
    rv = sympy.symbols(idaapi.get_reg_name(o.phrase, 32))
    if o.specflag1 != 0:
      rv = rv + sympy.symbols(idaapi.get_reg_name(o.specflag2, 32))
    rv = rv + (o.addr if o.addr < 2**31 else 2**32 - o.addr)
    return rv
