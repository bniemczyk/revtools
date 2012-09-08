#!/usr/bin/env python

import idc
import idaapi

def imports():
    idata = idc.SegByName('.idata')
