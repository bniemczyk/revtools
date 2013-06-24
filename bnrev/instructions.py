from symath import symbols

ADD,SUB,MUL,IMUL,DIV,IDIV = symbols('ADD SUB MUL IMUL DIV IDIV')
MOV,LEA = symbols('MOV LEA')
PUSH,POP,PUSHA,POPA = symbols('PUSH POP PUSHA POPA')
XOR,AND,OR = symbols('XOR AND OR')

tainted_dst_src_insts = set([
  ADD,SUB,MUL,IMUL,DIV,IDIV,MOV,XOR,AND,OR,LEA
  ])
