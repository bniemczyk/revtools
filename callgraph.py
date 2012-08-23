import directed

class CallGraph(directed.DirectedGraph):
    
    def __init__(self):
        import idautils
        super(CallGraph, self).__init__()
        for f in idautils.Functions():
            self.add_node(idautils.GetFunctionName(f))
            for cr in idautils.CodeRefsTo(f,0):
                self.connect(idautils.GetFunctionName(cr), idautils.GetFunctionName(f))
