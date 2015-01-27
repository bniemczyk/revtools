#!/usr/bin/env python

REQUIRED_VERIFICATION_BYTES = 2

def xor_check_string(needle, haystack, offset=0, keysize=4, get_xb=lambda keysize,offset,key: key[offset % keysize]):
  '''
  returns a key if the string is found, otherwise None
  '''

  assert(len(needle) >= keysize + REQUIRED_VERIFICATION_BYTES)

  if len(haystack) < len(needle) + offset:
    return None

  # is this a candidate?
  first_kb = ord(haystack[offset]) ^ ord(needle[0])
  if ord(haystack[offset+keysize]) ^ first_kb != ord(needle[keysize]):
    return None

  # calculate the key
  key = list(map(lambda i: ord(haystack[i + offset]) ^ ord(needle[i]), range(keysize)))

  # verify the rest of the bytes match our needle when run with our key
  for i in range(keysize, len(needle)):
    xb = get_xb(keysize, i, key)
    if ord(haystack[offset+i]) ^ xb != ord(needle[i]):
      return None

  # we don't care about unobfuscated strings
  keep = False
  for i in key:
    if i != 0:
      keep = True

  return key if keep == True else None

def check_prefixes(prefix_list, haystack, offset):
  r'''
  returns a list of (key,string) that are xor-encoded up to any \x00 | \x0a | \x0d | \x20
  '''

  for p in prefix_list:

    def _no_add_get_xb(keysize,offset,key):
      return key[offset % keysize]

    key = xor_check_string(p, haystack, keysize=4, offset=offset, get_xb=_no_add_get_xb)

    if key != None:
      # we found the needle!
      rv = []
      for i in range(len(haystack) - offset):
        xb = _no_add_get_xb(4,i,key)
        dc = xb ^ ord(haystack[offset+i])
        if dc in (0x0, 0xa, 0xd):
          break
        rv.append(dc)
      yield (key, "".join(map(chr, rv)))

def scan(prefix_list, haystack):
  for i in range(len(haystack)):
    for j in check_prefixes(prefix_list, haystack, i):
      yield j

if __name__ == '__main__':
  import getopt
  import sys
  import mmap

  prefixes = []

  default_prefixes = ['http://', 'https://', 'Software\\', 'This command']

  def _print_help():
      print r'''
      SUMMARY:

      scans a file for obfuscated strings beginning with certain prefixes (and cuts them off at newlines or \x00)
      prints out the key and then the string found
      
      '''
      print r'''
      usage: %s [options] <filenames>"

      OPTIONS:

      --prefix | -p <prefix>    Add <prefix> the list of string prefixes to search for, if this is not specified a default set of prefixes will be used
      ''' % (sys.argv[0],)

      sys.exit(0)

  (opts,args) = getopt.getopt(sys.argv[1:], "hp:", ["help", "prefix"])

  if len(args) < 1:
    _print_help()

  for (o,v) in opts:
    if o in ('-h', '--help'):
      _print_help()

    elif o in ('-p', '--prefix'):
      prefixes.append(v)

  if len(prefixes) == 0:
    prefixes = default_prefixes

  for arg in args:
    print '%s:' % (arg,)
    try:
        haystack = open(arg, 'rb').read()
        for (k,s) in scan(prefixes, haystack):
          print '%s: %s' % (k,s)

    except Exception, ex:
      print ex
