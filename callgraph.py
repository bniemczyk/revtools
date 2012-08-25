import directed

class CallGraph(directed.DirectedGraph):
    
    def __init__(self, includeImports=True):
        import idautils
        import idc
        import idaapi
        super(CallGraph, self).__init__()

        funcs = set(idautils.Functions())
        for f in funcs:
            self.add_node(idc.GetTrueName(f))
            for x in [x for x in idautils.FuncItems(f) if idaapi.is_call_insn(x)]:
                for xref in idautils.CodeRefsFrom(x,0):
                    if (not includeImports) and (not xref in funcs):
                        continue
                    n = idc.GetTrueName(xref)
                    if n != None and n != "":
                        self.connect(idc.GetTrueName(f), n)

    def tag_distance(self, function_name):
        import function
        import idc
        f = idc.LocByName(function_name)
        rv = {}

        for (n,l) in self.walk(function_name, direction='incoming'):
            if l == 0:
                continue

            function.tag(idc.LocByName(n), 'distance %s' % (function_name), l)
            rv[idc.LocByName(n)] = l

    def tag_recursive(self):
        import function
        import idautils
        import idc
        funcs = set(idautils.Functions())
        rv = {}

        for fa in funcs:

            f = idc.GetTrueName(fa)
            tags = []
            for stack in self.stackwalk(f):
                if self.connectedQ(stack[-1], f):
                    tags.append(stack)
            
            
            if len(tags) > 0:
                function.tag(idc.LocByName(f), 'recursive', tags)
                rv[fa] = len(tags)

        return rv

    def tag_popularity(self, context=None):
        import function
        import idautils
        import idc
        import algorithms
        funcs = set(idautils.Functions())
        rv = {}

        for fa in funcs:
            f = idc.GetTrueName(fa)
            p = algorithms.popularity(self, node=f, context=context)
            function.tag(fa, 'popularity', p)
            rv[fa] = p

        return rv

    def adjacency_matrix(self):
        print 'bulding adjacency matrix of call graph'
        rv = super(CallGraph, self).adjacency_matrix()
        print 'adjacency matrix built'
        return rv
