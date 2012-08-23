import directed

class CallGraph(directed.DirectedGraph):
    
    def __init__(self):
        import idautils
        import idc
        super(CallGraph, self).__init__()
        for f in idautils.Functions():
            self.add_node(idc.GetFunctionName(f))
            for cr in idautils.CodeRefsTo(f,0):
                self.connect(idc.GetFunctionName(cr), idc.GetFunctionName(f))
