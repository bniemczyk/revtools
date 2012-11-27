#!/usr/bin/env python
import idaapi
import idc
import idautils
import memoize

def safe_rename(h, name, flags):
  if idc.LocByName(name) == idc.BADADDR:
    return idc.MakeNameEx(h, name, flags)

  i = 1
  while idc.LocByName('%s_%x' % (name, i)) != idc.BADADDR:
    i += 1

  oldh = idc.LocByName(name)
  idc.MakeNameEx(oldh, '%s_%x' % (name, i), flags)
  return idc.MakeNameEx(h, name, flags)

def labelimports(imports_filename=r'c:\malware\default.exports.csv', startEA=None, endEA=None):
  print 'loading exports file'

  lines = open(imports_filename, 'r').readlines()
  exports = {}
  for i in lines:
    try:
      s = i.split(',')
      while s[1][-1] in ['\r', '\n']:
        s[1] = s[1][:-1]

      exports[int(s[0], 16)] = s[1]
    except:
      print 'could not parts %s' % (i)

  print 'adding comments'
  for h in idautils.Heads(startEA, endEA):
    dw = idc.Dword(h)
    if dw in exports:
      idc.MakeDword(h)
      #idc.MakeRptCmt(h, '[resolves to] %s' % (exports[dw]))
      safe_rename(h, exports[dw], idc.SN_WEAK|idc.SN_AUTO)
