#!/usr/bin/env python
from sympy import symbols

regs = {}
regs64 = {}
regs32 = {}
regs16 = {}
regs8 = {}

regs['flags'] = symbols('flags')

_clobbers = {}

def reg_symbol(regname):
    return regs[regname.lower()]

def regs_that_clobber(submissive):
    if type(submissive) == type(symbols('eax')):
        submissive = submissive.name

    for k in _clobbers:
        if submissive in _clobbers[k]:
            yield k

def regs_clobbered_by(dominate):
    if type(dominate) == type(symbols('eax')):
        dominate = dominate.name

    for i in _clobbers[dominate]:
        yield i

def _add_clobber(dominate, submissive):
    if dominate not in _clobbers:
        _clobbers[dominate] = set()

    _clobbers[dominate].add(submissive)
    for i in regs_that_clobber(dominate):
        _add_clobber(i, submissive)

for r in symbols('rax rbx rcx rdx rsi rdi rsp rbp r8 r9 r10 r11 r12 r13 r14 r15'):
    regs64[r.name] = r
    regs[r.name] = r

for r in symbols('eax ebx ecx edx esi edi esp ebp'):
    regs32[r.name] = r
    regs[r.name] = r
    _add_clobber('r' + r.name[1:], r.name)

for r in symbols('ax bx cx dx si di sp bp'):
    regs16[r.name] = r
    regs[r.name] = r
    _add_clobber('e' + r.name, r.name)

for r in symbols('ah al bh bl ch cl dh dl'):
    regs8[r.name] = r
    regs[r.name] = r
    _add_clobber(r.name[0] + 'x', r.name)
