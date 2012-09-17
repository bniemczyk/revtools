import idc
import idautils
import random
import function
import switch

def locate_vtables():
    heads = set(idautils.Heads())
    fns = set(idautils.Functions())

    for h in heads:
        if idc.isCode(h):
            continue

        xrefs = set(idautils.DataRefsTo(h))
        if len(xrefs) == 0:
            continue

        v = idc.Dword(h)
        if v not in fns:
            continue

        iss = False
        for x in xrefs:
            if switch.is_switch(x):
                iss = True
                break
        if iss:
            continue

        yield h

def analyze_vtables():
    vtables = set(locate_vtables())
    fns = set(idautils.Functions())

    for vt in vtables:
        # create a new class
        sname = "class_%x" % (vt)
        sid = idc.AddStruc(-1, sname)
        if sid == idc.BADADDR:
            sid = idc.GetStrucIdByName(sname)

        # create a struc for the vtable
        vname = "vtable_%x" % (vt)
        vid = idc.AddStruc(-1, vname)
        vfuncs = set()

        if vid == idc.BADADDR:
            vid = idc.GetStrucIdByName(vname)

        for i in range(0xffffff):
            target = idc.Dword(vt + (4 * i))

            if target not in fns:
                break

            if i > 0:
                # if there is a data ref, then it's probably the start of a new vtable
                xrefs = set(idautils.DataRefsTo(vt + (4 * i)))
                if len(xrefs) > 0:
                    continue

            idc.AddStrucMember(vid, 'vfunc_%x' % (i), -1, idc.FF_DWRD, -1, 4)

            # setup the target function
            function.tag(target, 'virtual table', hex(vt))
            vfuncs.add(target)

        # add a vtable to the new class
        idc.AddStrucMember(sid, 'vtable', 0, idc.FF_DWRD, -1, 4)

        # tag functions that reference the vtable as either a constructor or destructor
        # in order to do decide which, take advantage of a C++ thing, destructors will be
        # virtual, and constructors will not
        xrefs = idautils.DataRefsTo(vt)
        for r in xrefs:
            try:
                if xrefs in vfuncs:
                    function.tag(function.top(r), 'destructor', 'guessed from vtable (%x) analysis' % (vt))
                else:
                    function.tag(function.top(r), 'constructor', 'guessed from vtable (%x) analysis' % (vt))
            except:
                pass
