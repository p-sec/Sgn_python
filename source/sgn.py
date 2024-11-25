from random import randrange,seed
from keystone import *
from Comm import *


safeX86Prefix = [0x60, 0x9c] # PUSHAD, PUSHFD

safeX86Suffix = [0x9d, 0x61] # POPFD, POPAD

safeX64Prefix = [
    0x50, 0x53, 0x51, 0x52, # PUSH RAX,RBX,RCX,RDX
    0x56, 0x57, 0x55, 0x54, # PUSH RSI,RDI,RBP,RSP
    0x41, 0x50, 0x41, 0x51, # PUSH R8,R9
    0x41, 0x52, 0x41, 0x53, # PUSH R10,R11
    0x41, 0x54, 0x41, 0x55, # PUSH R12,R13
    0x41, 0x56, 0x41, 0x57, # PUSH R14,R15
]

safeX64Suffix = [
    0x41, 0x5f, 0x41, 0x5e, # POP R15,R14
    0x41, 0x5d, 0x41, 0x5c, # POP R13,R12
    0x41, 0x5b, 0x41, 0x5a, # POP R11,R10
    0x41, 0x59, 0x41, 0x58, # POP R9,R8
    0x5c, 0x5d, 0x5f, 0x5e, # POP RSP,RBP,RDI,RSI
    0x5a, 0x59, 0x5b, 0x58, # POP RDX,RCX,RBX,RAX
]


class REG :
    def __init__(self,Full,Extended,High,Low,arch) -> None:
        self.Full     = Full
        self.Extended = Extended
        self.High     = High
        self.Low      = Low
        self.arch     = arch


global REGS
REGS= dict()

REGS.setdefault(32,[]).append( REG("","EAX","AX",  "AL",32))
REGS.setdefault(32,[]).append( REG("","EBX","BX",  "BL",32))
REGS.setdefault(32,[]).append( REG("","ECX","CX",  "CL",32))
REGS.setdefault(32,[]).append( REG("","EDX","DX",  "DL",32))
REGS.setdefault(32,[]).append( REG("","ESI","SI",  "AL",32))
REGS.setdefault(32,[]).append( REG("","EDI","DI",  "BL",32))

REGS.setdefault(64,[]).append(REG("RAX", "EAX","AX",  "AL",64))
REGS.setdefault(64,[]).append(REG("RBX", "EBX","BX",  "BL",64))
REGS.setdefault(64,[]).append(REG("RCX", "ECX","CX",  "CL",64))
REGS.setdefault(64,[]).append(REG("RDX", "EDX","DX",  "DL",64))
REGS.setdefault(64,[]).append(REG("RSI", "ESI","SI",  "SIL",64))
REGS.setdefault(64,[]).append(REG("RDI", "EDI","DX",  "DIL",64))
REGS.setdefault(64,[]).append(REG("R8", "R8D","R8W",  "R8B",64))
REGS.setdefault(64,[]).append(REG("R9", "R9D","R9W",  "R9B",64))
REGS.setdefault(64,[]).append(REG("R10", "R10D","R10W",  "R10B",64))
REGS.setdefault(64,[]).append(REG("R11", "R11D","R11W",  "R11B",64))
REGS.setdefault(64,[]).append(REG("R12", "R12D","R12W",  "R12B",64))
REGS.setdefault(64,[]).append(REG("R13", "R13D","R13W",  "R13B",64))
REGS.setdefault(64,[]).append(REG("R14", "R14D","R14W",  "R14B",64))
REGS.setdefault(64,[]).append(REG("R15", "R15D","R15W",  "R15B",64))



global SafeRegisterPrefix
global SafeRegisterSuffix
SafeRegisterPrefix = dict()
SafeRegisterSuffix = dict()

SafeRegisterPrefix[32] = safeX86Prefix
SafeRegisterSuffix[32] = safeX86Suffix

SafeRegisterPrefix[64] = safeX64Prefix
SafeRegisterSuffix[64] = safeX64Suffix


#获取安全的可用的寄存器
def GetSafeRandomRegister(arch, regsize,ExcludesReg):
    while(True):
        Randreg = REGS[arch][randrange(0,len(REGS[arch]))]
        if (Randreg.Full        in ExcludesReg or
            Randreg.Extended    in ExcludesReg or
            Randreg.High        in ExcludesReg or 
            Randreg.Low         in ExcludesReg):
            continue

        if regsize == 8:
            return Randreg.Low
        elif regsize == 16:
            return Randreg.High
        elif regsize == 32:
            return Randreg.Extended
        elif regsize == 64:
            return Randreg.Full
        else:
            print("GetSafeRandomRegister invalid register size")

def GetRandomRegister(arch):
	if arch == 8:
		return REGS[arch][randrange(0,len(REGS[arch]))].Low
	elif arch == 16:
		return REGS[arch][randrange(0,len(REGS[arch]))].High
	elif arch == 32:
		return REGS[arch][randrange(0,len(REGS[arch]))].Extended
	elif arch == 64:
		return REGS[arch][randrange(0,len(REGS[arch]))].Full
	else:
		SetError("invalid register size")




def Assemble(arch,asm):
    if arch == 32:
        mode = KS_MODE_32
    elif arch == 64:
        mode = KS_MODE_64
    else:
        SetError("Assemble arch Error!")

    ks = Ks(KS_ARCH_X86,mode)
    try:
        encoding,count = ks.asm(asm)
    except KsError:
        encoding = []
        count = 0;

    return encoding,count

def GetRandomByte():
    return randrange(0,256)


