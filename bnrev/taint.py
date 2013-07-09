from idafun import symdecode
from idc import GetSpd,ScreenEA,GetSpDiff,SetColor,DEFCOLOR,CIC_ITEM

from functiongraph import FunctionGraph
from verdata import VersionedSet

from symath import wilds,WildResults,symbols
from symath.graph.directed import DirectedGraph
from symath.graph.algorithms import pathQ
from instructions import *

_colored = set()

def _color(ea, color=0x0000aa):
  global _colored

  SetColor(ea, CIC_ITEM, color)
  _colored.add(ea)

def _clear_colored():
  global _colored

  for i in _colored:
    SetColor(i, CIC_ITEM, DEFCOLOR)
  _colored = set()

def forward_data_flow(source, ea=None, calldepth=0):
  if ea == None:
    ea = ScreenEA()

  _clear_colored()

  inst,dst,src = wilds('inst dst src')
  w = WildResults()

  tainted = VersionedSet()
  tainted.version = -1
  tainted.add(source)

  def _fix_esp(ea, exp):
    spd = GetSpd(ea)
    return exp.substitute({esp: (esp + spd).simplify()})

  fg = FunctionGraph(ea)

  # data connections graph
  TAINTED = symbols('TAINTED')
  dg = DirectedGraph()
  dg.connect(TAINTED, source)
  
  for addr,level in fg.walk(ea, depthfirst=True):
    if level <= tainted.version:
      print 'reverting to version %s' % (level - 1)
      tainted = tainted.get_version(level - 1)

    tainted.version = level

    syminst = symdecode(addr)

    if syminst.match(inst(dst,src), w) and w.inst in tainted_dst_src_insts:
      print 'analyzing %s' % (syminst,)

      # untaint cleared registers
      if syminst.match(XOR(dst,dst)) and w.dst in tainted:
        tainted.remove(w.dst)

      elif w.src in tainted:
        _color(addr)
        print 'tainting %s' % (w.dst,)
        tainted.add(w.dst)

      elif w.dst in tainted:
        tainted.remove(w.dst)

  return tainted
