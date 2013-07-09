from symath import symbols

ADD,SUB,MUL,IMUL,DIV,IDIV = symbols('ADD SUB MUL IMUL DIV IDIV')
MOV,LEA = symbols('MOV LEA')
PUSH,POP,PUSHA,POPA = symbols('PUSH POP PUSHA POPA')
XOR,AND,OR = symbols('XOR AND OR')
SAR,SHR,SAL,SHL = symbols('SAR SHR SAL SHL')
INC,DEC = symbols('INC DEC')
MOVSX,MOVZX = symbols('MOVSX MOVZX')
CMP,TEST = symbols('CMP TEST')

control_flow_instructions = (JMP,JZ,JNZ,JA,JB,JNA,JNB,JE,JNE,JG,JL,JNG,JNL) = symbols('JMP JZ JNZ JA JB JNA JNB JE JNE JG JL JNG JNL')
