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
            refs = set(filter(lambda x: x >= start_addr and x <= end_addr, idautils.CodeRefsFrom(h,1)))
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
        for f in fns:
            fg = FunctionGraph(f)
            function.tag(fg.start_addr, 'cyclomatic complexity', fg.cyclomatic_complexity())


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

        fns = set(idautils.Functions())
        for f in fns:
            graphs[f] = FunctionGraph(f)
            _reversed[f] = FunctionGraph._tag_val(i, 'reversed') != None

        for i in fns:
            ac = 0
            if not _reversed[i]:
                for j,l in cg.walk(idc.GetTrueName(i), direction='outgoing'):
                    if _reversed[idc.LocByName(j)]:
                        continue
                    ac += graphs[idc.LocByName(j)].cyclomatic_complexity()

            function.tag(i, 'aggregate complexity', ac)
