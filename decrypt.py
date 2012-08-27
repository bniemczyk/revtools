#!/usr/bin/env python

def xor_decrypt(buf, key):
    if type(buf) == type('string'):
        buf = [ord(x) for x in buf]
    
    if type(key) == type('string'):
        key = [ord(x) for x in key]

    for i in range(len(buf)):
        d = i % len(key)
        buf[i] = buf[i] ^ key[d]

    return ''.join([chr(x) for x in buf])
