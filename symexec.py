#!/usr/bin/env python

import sympy
import symreg
import idaapi
import sys

# !FIXME!: 32-bit only stuff below!!
def get_signed(n):
    if n < sys.maxint:
        return n
    return -1 * (0x100000000 - n)

def regsize():
    return 4

### END 32 bit only ####

def sympify_ida_operand(op):
    Deref = sympy.symbols('Deref')

    if op.type == idaapi.o_reg:
        return symreg.regs[idaapi.get_reg_name(op.reg, regsize())]
    elif op.type == idaapi.o_mem:
        rv = sympy.sympify(op.addr)
        return Deref(sympy.sympify(op.addr))
    elif op.type == idaapi.o_imm:
        return sympy.sympify(op.value)
    elif op.type in (o_phrase, o_displ):
        rv = symreg.regs[idaapi.get_reg_name(op.reg, regsize())]
        if op.addr != 0:
            rv = rv + sympy.sympify(get_signed(op.addr))
        return Deref[rv]
    elif op.type == idaapi.o_near:
        return sympy.sympify(op.addr)
    else:
        raise "operand type %x not implemented" % (op.type)
