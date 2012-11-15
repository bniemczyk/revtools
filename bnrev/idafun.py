#!/usr/bin/env python

import idc
import idaapi
import idautils

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
