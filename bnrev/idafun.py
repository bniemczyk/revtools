#!/usr/bin/env python

import idc
import idaapi
import idautils
import distorm3

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

def decode(ea):
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
