from calculate import *
from symath import *
from idafun import symdecode
from hashable import HashableDict
from instructions import *
from idc import ScreenEA,GetSpd

import memoize

def symstep(addr=None, known=None):
  '''
  takes a HashableDict of known values and returns a copy of it that is updated
  after executing the instruction at addr
  '''

  if addr == None:
    addr = ScreenEA()

  if known == None:
    known = HashableDict()

  # use IDAs stack analysis, instead of tracking it ourselves, so we don't have to
  # ascend into all calls, also allows easier fixing by hand if required
  # this does mean that esp will always be reflected in known as though it's been calculated
  # from the beginning of the function instead of where ever we really started calculating,
  # but that is ok with me for now
  known = known.copy()
  known[esp] = (esp + GetSpd(addr))

  inst,src,dst = wilds('inst src dst')
  w = WildResults()

  si = symdecode(addr)

  exp = None

  if si.match(ADD(dst,src), w):
    exp = w.src + w.dst

  elif si.match(SUB(dst,src), w) or si.match(CMP(dst,src), w):
    exp = w.dst - w.src

  elif si.match(MUL(dst,src), w):
    exp = w.dst * w.src

  elif si.match(DIV(dst,src), w):
    exp = w.dst / w.src

  elif si.match(MOV(dst,src), w) or si.match(LEA(dst,src), w):
    exp = w.src

  elif si.match(XOR(dst, src), w):
    exp = w.dst ^ w.src

  elif si.match(OR(dst, src), w):
    exp = w.dst | w.src

  elif si.match(AND(dst, src), w) or si.match(TEST(dst, src), w):
    exp = w.dst & w.src

  elif si.match(SAR(dst, src), w) or si.match(SHR(dst, src), w):
    exp = w.dst >> w.src

  elif si.match(SAL(dst, src), w) or si.match(SHL(dst, src), w):
    exp = w.dst << w.src

  elif si.match(INC(dst), w):
    exp = w.dst + 1

  elif si.match(DEC(dst), w):
    exp = w.dst - 1

  elif si.match(PUSH(src), w):
    exp = w.src

  elif si.match(POP(dst), w):
    exp = DEREF(0x4, known[esp])

    if exp in known:
      exp = known[exp]

  # for control flow operations we just don't do anything
  elif si[0] in control_flow_instructions:
    return (None, known)

  exp = exp.simplify()
  exp = exp.substitute(known).simplify()

  # update our known
  if si.match(PUSH(src), w):
    dst = DEREF(0x4, known[esp]-4).simplify()

  elif exp != None and (si.match(inst(dst), w) or si.match(inst(dst, src), w)):
    dst = w.dst

    if w.dst[0] == DEREF:
      dst = w.dst.substitute(known).simplify()

  else:
    raise Exception("Uknown instruction in symstep: %s" % (si,))

  known[dst] = exp

  return (exp, known)


@memoize.Memoize
def _symmultistep(eas, known=None, expfunc=lambda ea,exp: exp):
  exp = None

  if len(eas) > 1:
    exp,known = _symmultistep(eas[:-1])

  exp,known = symstep(eas[-1], known=known)
  return expfunc(eas[-1], exp), known
