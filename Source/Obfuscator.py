from json import load
from os import rmdir
from random import Random, randint,sample,randrange
from string import ascii_letters ,digits
from sgn import *
from instructions import *


class Obfuscator:
    def __init__(self) -> None:
        self.arch = 0

    def GenerateGarbageInstructions(self):
        while (True):
            randomGarbageAssembly = self.GenerateGarbageAssembly()
            garbage,inssize = Assemble(self.arch , randomGarbageAssembly)
            if inssize != 0:
                SetInfo("[*] Garbage : -> {}".format(randomGarbageAssembly))
                break


        # if CoinFlip() {
        #     garbageJmp, err := GenerateGarbageJump()
        #     if err != nil {
        #         return nil, err
        #     }
        #     if CoinFlip() {
        #         garbage = append(garbageJmp, garbage...)
        #     } else {
        #         garbage = append(garbage, garbageJmp...)
        #     }
        # }

        # if len(garbage) <= encoder.ObfuscationLimit {
        #     //fmt.Println(randomGarbageAssembly)
        #     return garbage, nil
        # }

        return bytes(garbage)

    def GenerateGarbageAssembly(self):

        ra = randint(1,3)
        if ra == 1:
            randomGarbageAssembly = self.GetRandomSafeAssembly()
            register = GetRandomRegister(self.arch)
            randomGarbageAssembly = randomGarbageAssembly.format(
                R = register,
                K = hex(GetRandomByte()),
                L = self.RandomLabel(),
                G = self.GenerateGarbageAssembly())
            # if ("{G}" in randomGarbageAssembly):
            #     randomGarbageAssembly = randomGarbageAssembly.format(G =self.GenerateGarbageAssembly)

            # randomGarbageAssembly.replace("{R}", register)
            # randomGarbageAssembly.replace("{K}", hex(GetRandomByte()))
            # randomGarbageAssembly.replace("{L}", self.RandomLabel())
            # randomGarbageAssembly.replace("{G}", self.GenerateGarbageAssembly())
            randomGarbageAssembly += ";"
            return randomGarbageAssembly
        elif ra == 2:
            return "NOP;"
        else:
            return self.GetRandomFunctionAssembly()
        # elif ra == 3:
        #     pass
        # case 3:
        #     randRegister := encoder.GetSafeRandomRegister(encoder.architecture, encoder.GetStackPointer())
        #     // Save the destination register
        #     // After saving the target register to stack we can munipulate the register unlimited times
        #     unsafeGarbageAssembly := fmt.Sprintf("PUSH %s;", randRegister)
        #     if CoinFlip() {
        #         unsafeGarbageAssembly += encoder.GenerateGarbageAssembly()
        #     }
        #     unsafeGarbageAssembly += encoder.GetRandomUnsafeAssembly(randRegister)
        #     // Keep adding unsafe garbage by chance
        #     for {
        #         if CoinFlip() {
        #             unsafeGarbageAssembly += encoder.GetRandomUnsafeAssembly(randRegister)
        #         } else {
        #             break
        #         }
        #     }
        #     if CoinFlip() {
        #         unsafeGarbageAssembly += encoder.GenerateGarbageAssembly()
        #     }
        #     unsafeGarbageAssembly += fmt.Sprintf("POP %s;", randRegister)
        #     return unsafeGarbageAssembly


    # 返回一个安全的垃圾代码比如 jmp {L};{G};{L}:
    def GetRandomSafeAssembly(self):
        newSafeGarbageInstructions = SafeGarbageInstructions
        # Add garbage confditional jumps for more possibility
        for jmp in ConditionalJumpMnemonics:
            newSafeGarbageInstructions.append( jmp + " {L};{G};{L}:")

        return newSafeGarbageInstructions[randrange(0,len(SafeGarbageInstructions))]

    def RandomLabel(self):
        randlab = ''.join(sample(ascii_letters + digits, 5))
        return randlab

    # GetRandomFunctionAssembly generates a function frame assembly with garbage instructions inside
    def GetRandomFunctionAssembly(self):
        bp = ""
        sp = ""

        if self.arch == 32:
            bp = "EBP"
            sp = "ESP"
        elif self.arch == 64:
            bp = "RBP"
            sp = "RSP"
        else:
            SetError("GetRandomFunctionAssembly arch size error!")

        prologue ="PUSH {};".format(bp)
        prologue += "MOV {},{};".format(bp, sp)
        prologue += "SUB {},{};".format(sp, hex(GetRandomByte()))


        # Fill the function body with garbage instructions
        garbage = self.GenerateGarbageAssembly()

        epilogue = "MOV {},{};".format(sp, bp)
        epilogue += "POP {};".format(bp)

        return prologue + garbage + epilogue