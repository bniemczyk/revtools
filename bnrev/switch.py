#!/usr/bin/env python
import idc
import idautils

def is_switch(head):
    ist = idautils.DecodeInstruction(head)
    if ist == None:
        return False

    if ist.get_canon_mnem() not in ('call', 'jmp'):
        return False
    else:
        return ist.Operands[0].reg != 0
