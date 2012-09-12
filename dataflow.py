#!/usr/bin/env python

import algorithms

def is_mov_inst(ist):
    mov_ists = set(['mov'])
    return ist.get_canon_mnem() in mov_ists
