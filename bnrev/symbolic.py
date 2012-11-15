#!/usr/bin/env python
# this only exists because sympy crashes IDAPython
# for general use sympy is much more complete

from memoize import Memoize
import types
import copy
from hashable import HashableDict

def _order(a,b):
  '''
  used internally to put shit in canonical order
  '''
  if(isinstance(a, Number)):
    if(isinstance(b, Number)):
      return -1 if a < b else 0 if a == b else 1
    return (-1)
  else:
    return -1 if str(a) < str(b) else 0 if str(a) == str(b) else 1

class _Symbolic(tuple):

  def _canonicalize(self):
    '''
    overridden by some subtypes
     - should return a canonical version of itself
    '''
    return self

  def __eq__(self, other):
    return id(self) == id(other)

  def __ne__(self, other):
    return not self.__eq__(other)

  def __hash__(self):
    return id(self)

  def __getitem__(self, num):
    raise "getitem not supported"

  # arithmetic overrides
  def __mul__(self, other, commutative=True, associative=True):
    return Fn.Mul(self, other, commutative=commutative, associative=associative)

  def __div__(self, other, commutative=False, associative=False):
    return Fn.Div(self, other, commutative=commutative, associative=associative)

  def __add__(self, other, commutative=True, associative=True):
    return Fn.Add(self, other, commutative=commutative, associative=associative)

  def __sub__(self, other, commutative=False, associative=False):
    return Fn.Sub(self, other, commutative=commutative, associative=associative)

  def __or__(self, other, commutative=True, associative=True):
    return Fn.BitOr(self, other, commutative=commutative, associative=associative)

  def __and__(self, other, commutative=True, associative=True):
    return Fn.BitAnd(self, other, commutative=commutative, associative=associative)

  def __xor__(self, other, commutative=True, associative=False):
    return Fn.BitXor(self, other, commutative=commutative, associative=associative)

  def __rmul__(self, other, commutative=True, associative=True):
    return Fn.Mul(other, self, commutative=commutative, associative=associative)

  def __rdiv__(self, other, commutative=False, associative=False):
    return Fn.Div(other, self, commutative=commutative, associative=associative)

  def __radd__(self, other, commutative=True, associative=True):
    return Fn.Add(other, self, commutative=commutative, associative=associative)

  def __rsub__(self, other, commutative=False, associative=False):
    return Fn.Sub(other, self, commutative=commutative, associative=associative)

  def __ror__(self, other, commutative=True, associative=True):
    return Fn.BitOr(other, self, commutative=commutative, associative=associative)

  def __rand__(self, other, commutative=True, associative=True):
    return Fn.BitAnd(other, self, commutative=commutative, associative=associative)

  def __rxor__(self, other, commutative=True, associative=False):
    return Fn.BitXor(other, self, commutative=commutative, associative=associative)

  def __neg__(self):
    return self * -1

class Boolean(int):

  @Memoize
  def __new__(typ, b):
    self = int.__new__(typ, 1 if b else 0)
    self.name = str(b)
    self.boolean = b
    return self

  def __str__(self):
    return str(self.boolean)

  def __repr__(self):
    return str(self)

class Number(_Symbolic):

  IFORMAT = str
  FFORMAT = str

  @Memoize
  def __new__(typ, n):
    n = float(n)
    self = _Symbolic.__new__(typ)
    self.name = str(n)
    self.n = n
    return self

  def __str__(self):
    if self.n.is_integer():
      return Number.IFORMAT(int(self.n))
    else:
      return Number.FFORMAT(self.n)

  def __repr__(self):
    return str(self)

  # arithmetic overrides
  def __neg__(self):
    return symbolic(self.n.__neg__())

  def __mul__(self, other):
    if not isinstance(other, Number):
      other = symbolic(other)

    if isinstance(other, Number):
      return symbolic(self.n.__mul__(other.n))

    return symbolic(other.__rmul__(self.n))

  def __div__(self, other):
    if not isinstance(other, Number):
      other = symbolic(other)

    if isinstance(other, Number):
      return symbolic(self.n.__div__(other.n))

    return symbolic(other.__rdiv__(self.n))

  def __add__(self, other):
    if not isinstance(other, Number):
      other = symbolic(other)

    if isinstance(other, Number):
      return symbolic(self.n.__add__(other.n))

    return symbolic(other.__radd__(self.n))

  def __sub__(self, other):
    if not isinstance(other, Number):
      other = symbolic(other)

    if isinstance(other, Number):
      return symbolic(self.n.__sub__(other.n))

    return symbolic(other.__rsub__(self.n))

  def __or__(self, other):
    if not isinstance(other, Number):
      other = symbolic(other)

    if isinstance(other, Number):
      return symbolic(int(self.n).__or__(int(other.n)))

    return symbolic(int(other.n).__ror__(int(self.n)))

  def __and__(self, other):
    if not isinstance(other, Number):
      other = symbolic(other)

    if isinstance(other, Number):
      return symbolic(int(self.n).__and__(int(other.n)))

    return symbolic(int(other.n).__rand__(int(self.n)))

  def __xor__(self, other):
    if not isinstance(other, Number):
      other = symbolic(other)

    if isinstance(other, Number):
      return symbolic(int(self.n).__xor__(int(other.n)))

    return symbolic(int(other.n).__rxor__(int(self.n)))

  def __rmul__(self, other):
    if not isinstance(other, Number):
      other = symbolic(other)

    if isinstance(other, Number):
      return symbolic(self.n.__rmul__(other.n))

    return symbolic(other.__mul__(self.n))

  def __rdiv__(self, other):
    if not isinstance(other, Number):
      other = symbolic(other)

    if isinstance(other, Number):
      return symbolic(self.n.__rdiv__(other.n))

    return symbolic(other.__div__(self.n))

  def __radd__(self, other):
    if not isinstance(other, Number):
      other = symbolic(other)

    if isinstance(other, Number):
      return symbolic(self.n.__radd__(other.n))

    return symbolic(other.__add__(self.n))

  def __rsub__(self, other):
    if not isinstance(other, Number):
      other = symbolic(other)

    if isinstance(other, Number):
      return symbolic(self.n.__rsub__(other.n))

    return symbolic(other.__sub__(self.n))

  def __ror__(self, other):
    if not isinstance(other, Number):
      other = symbolic(other)

    if isinstance(other, Number):
      return symbolic(int(self.n).__ror__(int(other.n)))

    return symbolic(int(other.n).__or__(int(self.n)))

  def __rand__(self, other):
    if not isinstance(other, Number):
      other = symbolic(other)

    if isinstance(other, Number):
      return symbolic(int(self.n).__rand__(int(other.n)))

    return symbolic(int(other.n).__and__(int(self.n)))

  def __rxor__(self, other):
    if not isinstance(other, Number):
      other = symbolic(other)

    if isinstance(other, Number):
      return symbolic(int(self.n).__rxor__(int(other.n)))

    return symbolic(int(other.n).__xor__(int(self.n)))

class Wild(_Symbolic):
  '''
  wilds will not be equal even if they have the same name
  but the same *instance* will be equal to itself
  '''

  def __new__(typ, name, **kargs):
    self = _Symbolic.__new__(typ)
    self.name = name
    self.kargs = HashableDict(kargs)
    self.iswild = True
    return self

  def __str__(self):
    return self.name

  def __repr__(self):
    return str(self)

  def __call__(self, *args):
    return Fn(self, *args, **self.kargs)

class Symbol(Wild):
  '''
  symbols with the same name will be equal
  (and in fact are wilds guaranteed to be the same instance)
  '''

  @Memoize
  def __new__(typ, name, **kargs):
    self = Wild.__new__(typ, name)
    self.name = name
    self.kargs = HashableDict(kargs)
    self.iswild = False
    return self

class Fn(_Symbolic):

  @Memoize
  def __new__(typ, fn, *args, **kargs):
    '''
    arguments: Function, *arguments, **kargs
    valid keyword args:
      commutative (default False) - order of operands is unimportant
    '''
    args = map(symbolic, args)

    if len(args) == 2 and 'numeric' in kargs:
      x = args[0]
      y = args[1]
      if isinstance(x, Number) and isinstance(y, Number):
        if 'cast' in kargs and kargs['cast'] != None:
          x = kargs['cast'](x.n)
          y = kargs['cast'](y.n)
        else:
          x = x.n
          y = y.n
        return symbolic(getattr(x, kargs['numeric'])(y))

    if not isinstance(fn, _Symbolic):
      fn = symbolic(fn, **kargs)
      return Fn.__new__(typ, fn, *args, **kargs)

    redo = False
    for k in kargs:
      if k not in fn.kargs:
        fn.kargs[k] = kargs[k]
        redo = True

    for k in fn.kargs:
      if k not in kargs:
        kargs[k] = fn.kargs
        redo = True

    if redo:
      return Fn.__new__(typ, fn, *args, **kargs)

    self = _Symbolic.__new__(typ)

    if len(args) == 2:
      ridentity = kargs['ridentity'] if 'ridentity' in kargs else kargs['identity'] if 'identity' in kargs else None
      lidentity = kargs['lidentity'] if 'lidentity' in kargs else kargs['identity'] if 'identity' in kargs else None

      if lidentity != None and args[0] == lidentity:
        print 'simplifying %s(%s, %s)' % (fn, args[0], args[1])
        return args[1]

      if ridentity != None and args[1] == ridentity:
        print 'simplifying %s(%s, %s)' % (fn, args[0], args[1])
        return args[0]

    if 'zero' in kargs and kargs['zero'] in args:
      return kargs['zero']

    # if it's commutative, order the args in canonical order and call __new__ with that
    if 'commutative' in kargs and kargs['commutative']:
      args = list(args)
      args.sort(_order)
      kargs['commutative'] = False
      return Fn.__new__(typ, fn, *args, **kargs)

    self.name = fn.name
    self.fn = fn
    self.args = args
    self.kargs = HashableDict(kargs)

    return self._canonicalize()

  def __getitem__(self, n):
    if n == 0:
      return self.fn

    return self.args[n - 1]

  def _get_assoc_arguments(self):
    rv = []

    args = list(self.args)
    def _(a, b):
      if (isinstance(a, Fn) and a.fn == self.fn) and not (isinstance(b, Fn) and b.fn == self.fn):
        return -1

      if (isinstance(b, Fn) and b.fn == self.fn) and not (isinstance(a, Fn) and a.fn == self.fn):
        return 1

      return _order(a, b)

    args.sort(_)

    for i in args:
      if isinstance(i, Fn) and i.fn == self.fn:
        for j in i._get_assoc_arguments():
          rv.append(j)
      else:
        rv.append(i)

    return rv

  def _canonicalize(self):
    if 'canonicalize' in self.kargs and not self.kargs['canonicalize']:
      return self

    # canonicalize the arguments first
    args = list(map(lambda x: x._canonicalize(), self.args))
    if tuple(args) != tuple(self.args):
      self = Fn(self.fn, *args, **self.kargs)

    # if it's associative and one of the arguments is another instance of the
    # same function, canonicalize the order
    if len(self.args) == 2 and 'associative' in self.kargs and self.kargs['associative']:
      args = self._get_assoc_arguments()
      oldargs = tuple(args)
      args.sort(_order)
      if tuple(args) != oldargs:
        kargs = copy.copy(self.kargs)
        if 'canonicalize' in kargs:
          del kargs['canonicalize']
        self = reduce(lambda a, b: Fn(self.fn, a, b, canonicalize=False, **kargs), args)

    return self

  @staticmethod
  def LessThan(lhs, rhs, **kargs):
    return Fn(symbolic('<', **kargs), lhs, rhs, **kargs)

  @staticmethod
  def GreaterThan(lhs, rhs, **kargs):
    return Fn(symbolic('<', **kargs), rhs, lhs, **kargs)

  @staticmethod
  def LessThanEq(lhs, rhs, **kargs):
    return Fn(symbolic('<=', **kargs), lhs, rhs, **kargs)

  @staticmethod
  def GreaterThanEq(lhs, rhs, **kargs):
    return Fn(symbolic('<=', **kargs), rhs, lhs, **kargs)

  @staticmethod
  def Add(lhs, rhs, **kargs):
    return Fn(symbolic('+', **kargs), lhs, rhs, identity=symbolic(0), numeric='__add__', **kargs)

  @staticmethod
  def Sub(lhs, rhs, **kargs):
    return Fn(symbolic('-', **kargs), lhs, rhs, identity=symbolic(0), numeric='__sub__', **kargs)

  @staticmethod
  def Div(lhs, rhs, **kargs):
    return Fn(symbolic('/', **kargs), lhs, rhs, ridentity=symbolic(1), numeric='__div__', **kargs)

  @staticmethod
  def Mul(lhs, rhs, **kargs):
    return Fn(symbolic('*', **kargs), lhs, rhs, zero=symbolic(0), identity=symbolic(1), numeric='__mul__', **kargs)

  @staticmethod
  def RShift(lhs, rhs, **kargs):
    return Fn(symbolic('<<', **kargs), lhs, rhs, cast=int, ridentity=symbolic(0), numeric='__rshift__', **kargs)

  @staticmethod
  def LShift(lhs, rhs, **kargs):
    return Fn(symbolic('>>', **kargs), lhs, rhs, cast=int, ridentity=symbolic(0), numeric='__lshift__', **kargs)

  @staticmethod
  def BitAnd(lhs, rhs, **kargs):
    return Fn(symbolic('&', **kargs), lhs, rhs, cast=int, zero=symbolic(0), numeric='__and__', **kargs)

  @staticmethod
  def BitOr(lhs, rhs, **kargs):
    return Fn(symbolic('|', **kargs), lhs, rhs, cast=int, identity=symbolic(0), numeric='__or__', **kargs)

  @staticmethod
  def BitXor(lhs, rhs, **kargs):
    return Fn(symbolic('^', **kargs), lhs, rhs, cast=int, identity=symbolic(0), numeric='__xor__', **kargs)

  def __str__(self):
    if not self.name[0].isalnum() and len(self.args) == 2:
      return '(%s %s %s)' % (self.args[0], self.name, self.args[1])

    return '%s(%s)' % (self.name, ','.join(map(str, self.args)))

  def __repr__(self):
    return str(self)

def symbols(symstr):
  '''
  takes a string of symbols seperated by whitespace
  returns a tuple of symbols
  '''
  syms = symstr.split(' ')
  if len(syms) == 1:
    return Symbol(syms[0])

  rv = []
  for i in syms:
    rv.append(Symbol(i))

  return tuple(rv)

def wilds(symstr):
  '''
  takes a string of variable names seperated by whitespace
  returns a tuple of wilds
  '''
  syms = symstr.split(' ')
  if len(syms) == 1:
    return Wild(syms[0])

  rv = []
  for i in syms:
    rv.append(Wild(i))

  return tuple(rv)

def symbolic(obj, **kargs): 
  '''
  makes the symbolic version of an object
  '''
  if type(obj) in [type(0), type(0.0), type(0L)]:
    return Number(obj, **kargs)
  elif type(obj) == type('str'):
    return Symbol(obj, **kargs)
  elif type(obj) == type(True):
    return Boolean(obj, **kargs)
  elif isinstance(obj, _Symbolic):
    return obj
  else:
    raise "Unknown type passed to symbolic"

# for compatibility
def sympify(obj):
  return symbolic(obj)
