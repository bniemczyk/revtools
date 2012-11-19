#!/usr/bin/env python
# this only exists because sympy crashes IDAPython
# for general use sympy is much more complete

import traceback
from memoize import Memoize
import types
import copy
from hashable import HashableDict
import pprint
import operator

def _distribute(op1, op2, exp):
  '''
  TODO:
    will failed if op2/op1 are seen but do not have 2 operands

    FIXME: this can be change by specifying the order to walk
     but walk will need to be updated
    cannot use walk because it needs to distribute *before*
    running on the children
  '''
  if exp[0].name == op1.name:
    if exp[2][0].name == op2.name:
      args = list(map(lambda x: exp[0](exp[1], x), exp[2].args))
      exp = exp[2][0](*args)
    elif exp[1][0].name == op2.name:
      args = list(map(lambda x: exp[0](exp[2], x), exp[1].args))
      exp = exp[1][0](*args)

  if len(exp) > 1:
    args = list(map(lambda x: _distribute(op1, op2, x), exp.args))
    do_change = False
    for i in range(len(args)):
      if args[i] != exp.args[i]:
        do_change = True
        break
    if do_change:
      exp = exp[0](*args, **exp[0].kargs)

  return exp

def _simplify(exp):
  _and,_or,_mul,_add,_sub = symbols('& | * + -')
  exp = _distribute(_and, _or, exp)
  exp = _distribute(_mul, _add, exp)
  exp = _distribute(_mul, _sub, exp)
  return exp

def _order(a,b):
  '''
  used internally to put shit in canonical order
  '''
  if isinstance(a, Number):
    if(isinstance(b, Number)):
      return -1 if a.n < b.n else (0 if a.n == b.n else 1)
    return -1
  if isinstance(b, Number):
    return 1
  else:
    return -1 if str(a) < str(b) else (0 if str(a) == str(b) else 1)

class _Symbolic(tuple):

  def walk(self, fn):
    return fn(self)

  def _dump(self):
    return {
        'name': self.name,
        'id': id(self)
        }

  def _canonicalize(self):
    '''
    overridden by some subtypes
     - should return a canonical version of itself
    '''
    return self

  def substitute(self, subs):
    '''
    takes a dictionary of substitutions
    returns itself with substitutions made
    '''
    if self in subs:
      self = subs[self]

    return self

  def __eq__(self, other):
    return id(self) == id(other)

  def __ne__(self, other):
    return not self.__eq__(other)

  def __hash__(self):
    return id(self)

  def __getitem__(self, num):
    if num == 0:
      return self

    raise BaseException("Invalid index")

  def __len__(self):
    return 1

  # arithmetic overrides
  def __mul__(self, other, commutative=True, associative=True):
    return Fn.Mul(self, other, commutative=commutative, associative=associative)

  def __div__(self, other, commutative=False, associative=False):
    return Fn.Div(self, other, commutative=commutative, associative=associative)

  def __add__(self, other, commutative=True, associative=True):
    return Fn.Add(self, other, commutative=commutative, associative=associative)

  def __sub__(self, other, commutative=True, associative=True):
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

  def __rshift__(self, other, commutative=False, associative=False):
    return Fn.RShift(self, other, commutative=commutative, associative=associative)

  def __lshift__(self, other, commutative=False, associative=False):
    return Fn.LShift(self, other, commutative=commutative, associative=associative)

  def __rrshift__(self, other, commutative=False, associative=False):
    return Fn.RShift(other, self, commutative=commutative, associative=associative)

  def __rlshift__(self, other, commutative=False, associative=False):
    return Fn.LShift(other, self, commutative=commutative, associative=associative)

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

  def __eq__(self, other):
    if isinstance(other, _Symbolic):
      return super(Number, self).__eq__(other)
    else:
      return self.n == other

  def __ne__(self, other):
    if isinstance(other, _Symbolic):
      return super(Number, self).__ne__(other)
    else:
      return self.n != other

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
    other = symbolic(other)

    if isinstance(other, Number):
      return symbolic(int(self.n) | int(other.n))

    return other.__ror__(self)

  def __and__(self, other):
    other = symbolic(other)

    if isinstance(other, Number):
      return symbolic(int(self.n) & int(other.n))

    return symbolic(other).__rand__(int(self.n))

  def __xor__(self, other):
    other = symbolic(other)

    if isinstance(other, Number):
      return symbolic(int(self.n).__xor__(int(other.n)))

    return symbolic(other.__rxor__(int(self.n)))

  def __rshift__(self, other):
    other = symbolic(other)

    if isinstance(other, Number):
      return symbolic(int(self.n) >> int(other.n))

    return symbolic(other.__rrshift__(self))

  def __lshift__(self, other):
    other = symbolic(other)

    if isinstance(other, Number):
      return symbolic(int(self.n) << int(other.n))

    return symbolic(other.__rlshift__(self))

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
      return symbolic(int(self.n) ^ int(other.n))

    return symbolic(int(other.n) ^ int(self.n))

  def __rrshift__(self, other):
    other = symbolic(other)

    if isinstance(other, Number):
      return symbolic(int(other.n) >> int(self.n))

    return symbolic(other.__rshift__(self))

  def __rlshift__(self, other):
    other = symbolic(other)

    if isinstance(other, Number):
      return symbolic(int(other.n) >> int(self.n))

    return symbolic(other.__lshift__(self))

class Wild(_Symbolic):
  '''
  wilds will not be equal even if they have the same name
  but the same *instance* will be equal to itself

  the main part of this is for substituting patterns -
   this is not implemented yet
  '''

  def __new__(typ, name, **kargs):
    self = _Symbolic.__new__(typ)
    self.name = name
    self.kargs = kargs
    self.iswild = True
    return self

  def __str__(self):
    return self.name

  def __repr__(self):
    return str(self)

  def __call__(self, *args):
    return Fn(self, *args, **self.kargs)

  def _dump(self):
    return {
        'type': type(self),
        'name': self.name,
        'kargs': self.kargs,
        'iswild': self.iswild,
        'id': id(self)
        }

class Symbol(Wild):
  '''
  symbols with the same name will be equal
  (and in fact are wilds guaranteed to be the same instance)
  '''

  @Memoize
  def __new__(typ, name, **kargs):
    self = Wild.__new__(typ, name)
    self.name = name
    self.kargs = kargs
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
    orig_kargs = copy.copy(kargs)
    orig_args = copy.copy(args)

    for i in args:
      if not isinstance(i, _Symbolic):
        args = list(map(symbolic, args))
        return Fn.__new__(typ, fn, *args, **kargs)

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
        try:
          nfn = getattr(operator, kargs['numeric'])
          return symbolic(nfn(x,y))
        except:
          raise BaseException("Could not %s %s %s" % (x, kargs['numeric'], y))

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
        return args[1]

      if ridentity != None and args[1] == ridentity:
        return args[0]

    if 'zero' in kargs and kargs['zero'] in args:
      return kargs['zero']

    # if it's commutative, order the args in canonical order and call __new__ with that
    if 'commutative' in kargs and kargs['commutative']:
      args = list(args)
      oldargs = copy.copy(args)
      args.sort(cmp=_order)
      for i in range(len(args)):
        if oldargs[i] != args[i]:
          return Fn.__new__(typ, fn, *args, **kargs)

    self.name = fn.name
    self.fn = fn
    self.args = args
    self.kargs = kargs
    self.orig_kargs = orig_kargs
    self.orig_args = orig_args

    if self.fn.name == '+' and not self.kargs['associative']:
      print 'NON ASSOC ADDITION'
      traceback.print_stack()

    rv = _simplify(self._canonicalize())._canonicalize()

    #if rv[0].name == '+':
      #print rv
      #p = pprint.PrettyPrinter(indent=2)
      #p.pprint(rv._dump())

    return rv

  def _dump(self):
    return {
        'id': id(self),
        'name': self.name,
        'fn': self.fn._dump(),
        'kargs': self.kargs,
        'args': list(map(lambda x: x._dump(), self.args)),
        'orig kargs': self.orig_kargs,
        'orig args': list(map(lambda x: x._dump(), self.orig_args))
        }

  def walk(self, fn):
    args = map(lambda x: x.walk(fn), self.args)
    return fn(self.fn(*args))

  def substitute(self, subs):
    args = list(map(lambda x: x.substitute(subs), self.args))
    self = Fn(self.fn, *args, **self.kargs)

    if self in subs:
      self = subs[self]

    return self

  def __getitem__(self, n):
    if n == 0:
      return self.fn

    return self.args[n - 1]

  def __len__(self):
    return len(self.args) + 1

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
        self = reduce(lambda a, b: Fn(self.fn, a, b, **kargs), args)

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
    #return Fn(symbolic('-', **kargs), lhs, rhs, identity=symbolic(0), numeric='__sub__', **kargs)
    return Fn.Add(lhs, -rhs, **kargs)

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
    if lhs == rhs:
      return symbolic(0)
    return Fn(symbolic('^', **kargs), lhs, rhs, cast=int, identity=symbolic(0), numeric='__xor__', **kargs)

  def __str__(self):
    if not self.name[0].isalnum() and len(self.args) == 2:
      return '(%s %s %s)' % (self.args[0], self.name, self.args[1])

    return '%s(%s)' % (self.name, ','.join(map(str, self.args)))

  def __repr__(self):
    return str(self)

def symbols(symstr, **kargs):
  '''
  takes a string of symbols seperated by whitespace
  returns a tuple of symbols
  '''
  syms = symstr.split(' ')
  if len(syms) == 1:
    return Symbol(syms[0], **kargs)

  rv = []
  for i in syms:
    rv.append(Symbol(i, **kargs))

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
    msg = "Unknown type (%s) %s passed to symbolic" % (type(obj), obj)
    raise BaseException(msg)

# for compatibility
def sympify(obj):
  return symbolic(obj)
