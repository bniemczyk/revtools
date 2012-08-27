#!/usr/bin/env python
import os
import pefile

def dump(fname, names=None, decryptor=lambda x: x):
    pe = pefile.PE(fname)
    mm = pe.get_memory_mapped_image()

    rd = pe.DIRECTORY_ENTRY_RESOURCE
    if not os.path.exists('resources'):
        os.mkdir('resources')

    for ent in rd.entries:
        if names != None:
            if (ent.name == None or ent.name.string not in names) and ent.id not in names:
                continue

        fname = '%s' % (hex(ent.id) if ent.id != None else 'noid')
        if ent.name != None:
            fname = '%s_%s' % (hex(ent.id) if ent.id != None else 'noid', ent.name.string)

        # locate the data entry
        e = ent
        while e != None and not hasattr(e, 'data'):
            e = e.directory.entries[0]

        if e == None:
            print 'could not find data for %s' % (fname)
            continue

        data = e.data
        rva = data.struct.OffsetToData
        size = data.struct.Size
        data = mm[rva:rva+size]
        data = decryptor(data)

        print 'writing %s' % (fname)
        f = open('resources/%s' % (fname,), 'wb')
        f.write(data)
        f.close()
