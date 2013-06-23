#/usr/bin/env python

import automata

def search_for_string(needle, haystack):

  nfa = automata.NFA((0,0))
  for i in range(256):
    nfa.add_transition((0,0), automata.NFA.EPSILON, (0,i))
    for j in range(len(needle)):
      nfa.add_transition((j,i), automata.NFA.EPSILON, (j+1,i))
    nfa.add_final_state((i,len(needle)))

  return nfa.execute(haystack)
