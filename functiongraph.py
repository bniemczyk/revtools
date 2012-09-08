#!/usr/bin/env
import directed

class FunctionGraph(directed.DirectedGraph):

    def __init__(self, functionName):
        import idautils
        import idc
        import idaapi
        super(FunctionGraph, self).__init__()

        start_addr = idc.LocByName(functionName) if type(functionName) == type('str') else functionName
        end_addr = idc.FindFuncEnd(start_addr)

        self.start_addr = start_addr
        self.end_addr = end_addr

        for h in idautils.Heads(start_addr, end_addr):
            if h == idc.BADADDR:
                continue
            if not idc.isCode(idc.GetFlags(h)):
                continue


            self.add_node(h)
            mnem = idc.GetMnem(h)
            if mnem == 'retn':
                self.exit_nodes.add(h)

            refs = set(filter(lambda x: x <= end_addr and x >= start_addr, idautils.CodeRefsFrom(h,1)))
            nh = idc.NextHead(h, end_addr)
            if nh != idc.BADADDR and idc.isFlow(nh):
                refs.add(nh)

            for r in refs:
                self.connect(h, r)

    @staticmethod
    def tag_cyclomatic_complexity():
        import function
        import idc
        import idautils

        fns = set(idautils.Functions())
        rv = {}

        for f in fns:
            fg = FunctionGraph(f)
            c = fg.cyclomatic_complexity()
            if c < 0:
                c = 0
            function.tag(fg.start_addr, 'cyclomatic complexity', c)
            rv[f] = c

        return rv

    @staticmethod
    def tag_xors():
        import function
        import idc
        import idautils
        import algorithms

        fns = set(idautils.Functions())
        rv = {}

        for f in fns:
            #print 'analyzing %x for xor loops' % (f)
            fg = FunctionGraph(f)
            rv[f] = False
            for n in fg.nodes:
                m = idc.GetMnem(n)
                if m != 'xor':
                    continue
                op0 = idc.GetOpnd(n,0)
                op1 = idc.GetOpnd(n,1)
                if op0 != op1 and n in algorithms.find_cylic_nodes(fg,f):
                    function.tag(f, 'xor in loop', True)
                    rv[f] = True
                    break

        return rv

    @staticmethod
    def _tag_val(addr, tagname, default=None):
        import function
        try:
            return function.tag(addr, tagname)
        except:
            return default

    @staticmethod
    def tag_aggregate_complexity():
        import function
        import idc
        import idautils
        import callgraph

        cg = callgraph.CallGraph(includeImports=False)

        graphs = {}
        _reversed = {}
        rv = {}

        fns = set(idautils.Functions())
        cc = {}

        for f in fns:
            graphs[f] = FunctionGraph(f)
            _reversed[f] = FunctionGraph._tag_val(f, 'reversed') != None
            if _reversed[f]:
                cg.strip_edges_to(idc.GetTrueName(f))

        for i in fns:
            ac = 0
            for j,l in cg.walk(idc.GetTrueName(i), direction='outgoing'):
                loc = idc.LocByName(j)
                if loc not in cc:
                    cc[loc] = graphs[loc].cyclomatic_complexity()
                ac += cc[loc] if cc[loc] > 0 else 0

            function.tag(i, 'aggregate complexity', ac)
            rv[i] = ac

        return rv

    @staticmethod
    def analyze_loops():
        import idc
        import idautils
        import algorithms

        for fn in idautils.Functions():
            fg = FunctionGraph(fn)
            ds = algorithms.dominate_sets(fg, fn)
            hs = list(algorithms.loop_headers(fg, ds, fn))
            hs.sort()
            if len(hs) == 1:
                idc.MakeNameEx(hs[0], '_loop', idc.SN_LOCAL)
            elif len(hs) > 1:
                for i in range(len(hs)):
                    idc.MakeNameEx(hs[i], '_loop_%d' % (i+1), idc.SN_LOCAL)
