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

    def tag_distance(self, function_name):
        import function
        import idc
        f = idc.LocByName(function_name)

        for (n,l) in self.walk(function_name, direction='incoming'):
            if l == 0:
                continue

            function.tag(idc.LocByName(n), 'distance %s' % (function_name), l)
