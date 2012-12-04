#!/usr/bin/env python
import idc
import re

def tag(ea, name, value):
  cmt = idc.GetFunctionCmt(ea, True)
  if cmt == None:
    cmt = ''
  if ('[' + name + ']') in cmt:
    cmt = re.sub(r'\[%s\].*' % (name), '[' + name + '] ' + value, cmt)

  idc.SetFunctionCmt(ea, cmt, True)
