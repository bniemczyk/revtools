#!/usr/bin/env python

import idc
import idaapi
import idautils
import distorm3
import symath
import calculate as calc
from memoize import Memoize

def op_size(op):
  if op.dtyp in [0]:
    return 1
  elif op.dtyp in [1]:
    return 2
  elif op.dtyp in [2,3]:
    return 4
  elif op.dtyp in [4,7]:
    return 8

  raise "Unknown operand type"

def decode(ea=None):
  if ea == None:
    ea = idc.ScreenEA()

  ist = idautils.DecodeInstruction(ea)
  if ist == None:
    return None

  _bytes = map(lambda x: chr(idc.Byte(ea+x)), range(ist.size))
  _bytes = ''.join(_bytes)

  ist = distorm3.Decompose(ea, _bytes)[0]

  # distorm doesn't decode the operand logical size ie.. byte ptr, so use IDA for that
  for i in range(len(ist.operands)):
    idaop = idautils.DecodeInstruction(ist.address)[i]
    setattr(ist.operands[i], 'op_size', op_size(idaop))

  return ist

@Memoize
def _symdecode(ea):
  assert ea != None
  ist = decode(ea)
  mnem = symath.symbolic(ist.mnemonic)
  def _resolve_ops(n):
    rv = []
    for i in range(n):
      rv.append(calc.resolve_op(ist, i))
    return tuple(rv) if n > 1 else (rv[0],)
  ops = _resolve_ops(len(ist.operands))
  ops = map(lambda x: x.simplify(), ops)
  return mnem(*ops)

def symdecode(ea=None):
  return _symdecode(ea if ea != None else idc.ScreenEA())
