#!/usr/bin/env python
import idc
import idautils
import re
#from x86symexec.registers import *
#from x86symexec.ida import decode
import symath
import functiongraph
import copy
import sqlite3

def tag(ea, name, value):
  cmt = idc.GetFunctionCmt(ea, True)
  if cmt == None:
    cmt = ''

  value = str(value)

  if ('[' + name + ']') in cmt:
    cmt = re.sub(r'\[%s\].*' % (name), '[' + name + '] ' + value, cmt)
  else:
    cmt = cmt + '\n' + '[' + name + '] ' + value

  idc.SetFunctionCmt(ea, cmt, True)

# def signature(ea=None):
#   if ea == None:
#     ea = idc.ScreenEA()
# 
#   off = symath.symbols('off')
#   _signature = symath.symbols('signature')
# 
#   fg = functiongraph.FunctionGraph(ea)
#   ns = copy.copy(fg.nodes.keys())
#   ns.sort()
#   rv = []
# 
#   def _(exp):
#     if isinstance(exp, symath.Number) and int(exp.n) in ns:
#       return off(ns.index(int(exp.n)))
#     elif is_register(exp) and exp not in (ESP,):
#       return symath.wild(str(exp))
#     else:
#       return exp
# 
#   for i in ns:
#     rv.append(decode(i).walk(_))
# 
#   return _signature(*rv)
# 
# def mksignaturedb(dbname):
#   with sqlite3.connect(dbname) as con:
#       cur = con.cursor()
# 
#       try:
#         cur.execute('create table signatures (ea int not null, signature string not null)')
#       except:
#         cur.execute('delete from signatures')
# 
#       for fn in idautils.Functions():
#         print 'generating signature for %x' % (fn)
#         sig = signature(fn)
#         cur.execute('insert into signatures (ea, signature) values (?, ?)', (fn, str(sig)))
# 
#       con.commit()
