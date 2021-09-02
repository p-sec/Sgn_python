from datetime import datetime
from decode import Decode
from sgn import *
from Obfuscator import Obfuscator


OPERANDS = ["XOR", "SUB", "ADD", "ROL", "ROR", "NOT"]

# SCHEMA contains the operand and keys to apply single step encoding
class SCHEMA ():
    def __init__(self) -> None:
        self.OP = ""
        self.Key= ''


class Encoder(Decode,Obfuscator):
    def __init__(self):
        seed(datetime.now())
        self.arch		= 32    
        self.ObfuscationLimit 	= 50
        self.PlainDecoder     	= True
        self.Key                = randrange(0,256)
        self.EncodingCount    	= 0
        self.SaveRegisters    	= 0
        self.Error              = ''
        self.REGS               = REGS
        self.obfuscator         = Obfuscator()

    def SetArchitecture(self,ARCH):
        if ARCH == 32:
            self.arch = 32
        elif ARCH ==64:
            self.arch = 64
        else :
            self.SetError("invalid arch")

 
    def Encode(self,Payload):
        #返回一块汇编格式垃圾代码
        if self.SaveRegisters:
            Payload = Payload + SafeRegisterSuffix[self.architecture]

        Garbage = self.GenerateGarbageInstructions()
        Payload = Garbage + Payload
        cipheredPayload = self.CipherADFL(Payload,self.Key)
        encodedPayload = self.AddADFLDecoder(cipheredPayload)
        #return  encodedPayload


        # Add more garbage instrctions before the decoder stub
        garbage = self.GenerateGarbageInstructions()

        Payload = Garbage + Payload

        #// Calculate schema size
        schemaSize = ((len(encodedPayload) - len(cipheredPayload)) / (self.arch / 8)) + 1
        randomSchema = self.NewCipherSchema(schemaSize)

        obfuscatedEncodedPayload = self.SchemaCipher(encodedPayload, 0, randomSchema)
        final  = self.AddSchemaDecoder(obfuscatedEncodedPayload, randomSchema)

        while self.EncodingCount > 1:
            self.EncodingCount = self.EncodingCount - 1
            self.Seed = GetRandomByte()
            final = self.Encode(final)


        if self.SaveRegisters:
            final =  SafeRegisterPrefix[self.arch] + final

        return final 

    def CipherADFL(self,Payload,Key):
        EnCrypt = ['' for t1 in range(len(Payload))]
        for index in range(len(Payload)-1,-1,-1):
            OrgValue = Payload[index]
            EnCrypt[index] = Payload[index] ^ Key
            Key = (Key + OrgValue) & 0xFF
        return EnCrypt

    def NewCipherSchema(self,num):

        schema = [SCHEMA for i in range(num)]

        for cursor in schema:
            cursor.OP = self.RandomOperand()
            # cursor.OP = "XOR"
            if cursor.OP == "NOT":
                cursor.Key = None
            elif cursor.OP == "ROL" or cursor.OP == "ROR" : 
                cursor.Key = [0, 0, 0, GetRandomByte()]
            else :
                cursor.Key = [GetRandomByte(), GetRandomByte(), GetRandomByte(), GetRandomByte()]
            #schema[i] = cursor
        return schema

    def RandomOperand(self):
	    return OPERANDS[randrange(len(OPERANDS))]

    def SchemaCipher(self,data,index,schema):
        for cursor in schema:
            # if cursor.OP == "XOR":
            #     binary.BigEndian.PutUint32(data[index:index+4], (binary.BigEndian.Uint32(data[index:index+4]) ^ binary.LittleEndian.Uint32(cursor.Key)))
            # elif cursor.OP == "ADD":
            #     binary.LittleEndian.PutUint32(data[index:index+4], (binary.LittleEndian.Uint32(data[index:index+4])-binary.BigEndian.Uint32(cursor.Key))%0xFFFFFFFF)
            # elif cursor.OP == "SUB":
            #     binary.LittleEndian.PutUint32(data[index:index+4], (binary.LittleEndian.Uint32(data[index:index+4])+binary.BigEndian.Uint32(cursor.Key))%0xFFFFFFFF)
            # elif cursor.OP == "ROL":
            #     binary.LittleEndian.PutUint32(data[index:index+4], bits.RotateLeft32(binary.LittleEndian.Uint32(data[index:index+4]), -int(binary.BigEndian.Uint32(cursor.Key))))
            # elif cursor.OP == "ROR":
            #     binary.LittleEndian.PutUint32(data[index:index+4], bits.RotateLeft32(binary.LittleEndian.Uint32(data[index:index+4]), int(binary.BigEndian.Uint32(cursor.Key))))
            # elif cursor.OP == "NOT":
            #     binary.BigEndian.PutUint32(data[index:index+4], (^binary.BigEndian.Uint32(data[index : index+4])))
            # else :
            #     SetError("SchemaCipher cursor.OP Error")
            index += 4
        return data

    def AddCallOver(self, payload) :

        # Perform a shport call over the payload
        call = "call {}".format(hex(len(payload)+5))
        callBin, ok = Assemble(call)
        if ok == 0:
            SetError("call-over assembly failed")

        payload  = callBin + payload
        return payload

    def  AddSchemaDecoder(self, payload, schema) :

        index = 0

        # Add garbage instrctions before the ciphered decoder stub
        garbage = self.GenerateGarbageInstructions()
        
        payload = garbage + payload
        index += len(garbage)

        # Add call instruction over the ciphered payload
        payload = self.AddCallOver(payload)


        # Add garbage instrctions after the ciphered decoder stub
        garbage  = self.GenerateGarbageInstructions()
        
        payload = garbage + payload

        reg = GetRandomRegister(self.arch)

        # Toss a coin for get the garbage+decoder address to register by pop or mov
        if self.CoinFlip():
            pop = Assemble("POP {};".format(reg))  # !!
            payload =   payload + pop 

        else :
            mov = Assemble("MOV {},[{}];", reg, self.GetStackPointer()) 
            sub = Assemble("SUB {},{};", self.GetStackPointer(), hex(self.arch/8)) 
            payload = payload + mov + sub

        for  cursor in schema :

            # Mandatory obfuscation with coin flip for true polimorphism
            garbage = self.GenerateGarbageInstructions()
            
            payload = payload + garbage

            stepAssembly = ""
            if cursor.Key == None:
                stepAssembly += "\t{} DWORD PTR [{}+{}];\n".format(cursor.OP, reg, hex(index))
            else :
                stepAssembly +="\t{} DWORD PTR [{}+{}],{};\n".format(cursor.OP, reg, hex(index), hex(binary.BigEndian.Uint32(cursor.Key)))

            #fmt.Println(stepAssembly)
            decipherStep = Assemble(stepAssembly)

            payload = payload + decipherStep
            index += 4

        # More possibilities...
        returnAssembly = ""
        if self.CoinFlip():
            returnAssembly = "jmp {};".format(reg)
        else :
            returnAssembly = "push {};ret;".format(reg)


        returnInstruction = self.Assemble(returnAssembly)

        garbage = self.GenerateGarbageInstructions()

        payload = payload + returnInstruction + garbage

        
        

        return payload

    def CoinFlip(self):
	    return randrange(0,2) == 0
    
    # GetStackPointer returns the stack pointer register string based on the encoder architecture
    def GetStackPointer(self):

        if self.arch == 32:
            return "ESP"
        elif self.arch == 64:
            return "RSP"
        else:
            SetError("GetStackPointer invalid architecture")
