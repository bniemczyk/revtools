#!/usr/bin/env python

import math
import functiongraph
import callgraph
import function
import idautils
import idc
import idaapi

def _invert(dic):
    for k in dic:
        dic[k] = 1.0 / dic[k] if dic[k] != 0.0 else 0.0
    return dic

def _add_one(dic):
    for k in dic:
        dic[k] = 1.0 + dic[k]

def _coderefscount():
    fs = set(idautils.Functions())
    rv = {}
    for f in fs:
        rv[f] = len(set(idautils.CodeRefsTo(f,1)))
    return rv

# individual rules
COMPLEXITY = lambda ctx: _invert(functiongraph.FunctionGraph.tag_aggregate_complexity())
POPULARITY = lambda ctx: callgraph.CallGraph().tag_popularity(context=ctx)
XREFCOUNT = lambda ctx: _coderefscount()

def DISTANCE(target,direction='outgoing'):
    return lambda ctx: _invert(callgraph.CallGraph().tag_distance(target,direction=direction))

def PROXIMITY_RULESET(target):
    return set((COMPLEXITY, DISTANCE(target,direction='either')));

# handy rulesets
DEFAULT_RULESET = set((COMPLEXITY, (POPULARITY, 0.7), (XREFCOUNT, 0.7)))

# takes a list of rules (defined above) or tuples (rule, weight).  In the
# former case, weight = 1.0 is assumed
#
# calculates a priority for all functions by taking a weighted geomean of
# individual rule scores
def prioritize(ruleset=DEFAULT_RULESET, context=None):
    ruleset = list(ruleset)

    # make all weights explicit
    for i in range(len(ruleset)):
        if type(ruleset[i]) != type((1,1)):
            print 'using default weight of 1.0 for %s' % (ruleset[i],)
            ruleset[i] = (ruleset[i], 1.0)

    numerator = {}
    denominator = {}
    zeros = {}

    fns = set(idautils.Functions())
    for f in fns:
        numerator[f] = 0.0
        denominator[f] = 0.0
        zeros[f] = False

    for (rule,weight) in ruleset:
        d = rule(context)
        for f in fns:
            if f not in d:
                continue
            if d[f] == 0:
                zeros[f] = True
            else:
                numerator[f] += float(weight) * math.log(float(d[f]))
                denominator[f] += float(weight)

    for f in fns:
        if denominator[f] != 0.0 and not zeros[f]:
            numerator[f] = math.exp(numerator[f] / denominator[f])
        else:
            numerator[f] = 0.0

        function.tag(f, 'priority', numerator[f])

    return numerator
