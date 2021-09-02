from sgn import *
from Comm import *

x86DecoderStub = '''
    CALL getip
getip:
    POP {R}
    MOV ECX,{S}
    MOV {RL},{K}
decode:
    XOR BYTE PTR [{R}+ECX+data-6],{RL}
    ADD {RL},BYTE PTR [{R}+ECX+data-6]
    LOOP decode
data:
'''

x64DecoderStub = '''
    MOV {RL},{K}
    MOV RCX,{S}
    LEA {R},[RIP+data-1]
decode:
    XOR BYTE PTR [{R}+RCX],{RL}
    ADD {RL},BYTE PTR [{R}+RCX]
    LOOP decode
data:
'''

global STUB
STUB = dict()

STUB[32] = x86DecoderStub
STUB[64] = x64DecoderStub

class Decode:
    def __init__(self):
        pass
    
    #将解码Stub转换成汇编格式加入到payload中
    def AddADFLDecoder(self,payload):
        decoderAssemblyStub = self.NewDecoderAssembly(len(payload))
        decoderAssembly,asmSize = Assemble(self.arch,decoderAssemblyStub)
        return decoderAssembly + payload

    #返回解码Stub片段
    def NewDecoderAssembly(self,payloadSize):
        decoderStub = STUB[self.arch]
        reg = GetSafeRandomRegister(self.arch,32, ["ECX"])
        regL = GetSafeRandomRegister(self.arch, 8 ,[reg, "CL"])

        decoderStub = decoderStub.format(
            R   = reg,
            RL  = regL,
            K   = hex(self.Key),
            S   =  hex(payloadSize)
        )

        # decoderStub.replace("{R}", reg)
        # decoderStub.replace("{RL}", regL)
        # decoderStub.replace("{K}", hex(self.Key))
        # decoderStub.replace("{S}", hex(payloadSize))

        SetInfo( "[*] decoderStub ->  {}".format(decoderStub))
        return decoderStub

    