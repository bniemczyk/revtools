#/usr/bin/env python

import automatamm as automata

def _action():
  print 'found'

def search_for_string(needle, haystack):

  nfa = automata.NFA((0,0))
  for i in range(256):
    nfa.add_transition((0,0), automata.EPSILON, (0,i))
    for j in range(len(needle)):
      nfa.add_transition((j,i), automata.EPSILON, (j+1,i))
    nfa.set_action((i,len(needle)), _action)

  return nfa.execute(haystack)

if __name__ == '__main__':
  import sys
  needle = sys.argv[1]
  for haystack in sys.argv[2:]:
    print 'searching %s' % (haystack,)
    data = open(haystack, 'rb').read()
    search_for_string(needle, data)
