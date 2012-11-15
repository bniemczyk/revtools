#!/usr/bin/env python

import symbolic

from idafun import *

UNKNOWN_IMM = object()

def resolve_op(ist, opnum):
  o = ist[opnum]
  os = op_size(o)

  if o.type == idaapi.o_reg:
    return symbolic.symbols(idaapi.get_reg_name(o.reg, 4))

  if o.type == idaapi.o_imm:
    return symbolic.symbolic(o.value)

  if o.type == idaapi.o_displ:
    rv = symbolic.symbols(idaapi.get_reg_name(o.phrase, 4))
    #if o.specflag1 != 0:
    #  rv = rv + symbolic.symbols(idaapi.get_reg_name(o.specflag2, 4))
    rv = rv + (o.addr if o.addr < 2**31 else 2**32 - o.addr)
    return rv
