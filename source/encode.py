from datetime import datetime
from decode import Decode
from sgn import *
from Obfuscator import Obfuscator


OPERANDS = ["XOR", "SUB", "ADD", "ROL", "ROR", "NOT"]

# SCHEMA contains the operand and keys to apply single step encoding
class SCHEMA ():
    def __init__(self) :
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
        schemaSize = int(((len(encodedPayload) - len(cipheredPayload)) / (self.arch / 8)) + 1)
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
        schema = [SCHEMA() for i in range(num)]
        for cursor in schema:
            cursor.OP = self.RandomOperand()
            # cursor.OP = "XOR"
            if cursor.OP == "NOT":
                cursor.Key = None
            elif cursor.OP == "ROL" or cursor.OP == "ROR" or cursor.OP == "ADD" or cursor.OP == "SUB" :
                cursor.Key = [GetRandomByte(),0, 0, 0]
            else :
                cursor.Key = [GetRandomByte(), GetRandomByte(), GetRandomByte(), GetRandomByte()]
            #schema[i] = cursor
        return schema

    def RandomOperand(self):
	    return OPERANDS[randrange(len(OPERANDS))]
    def set_dword_offset(self,source_data,dword_data,offset):
        if not isinstance(source_data, bytes):
            raise TypeError('data should be of type: bytes')
        if 0 <= offset < len(source_data):
            newdata = ( source_data[:offset] + dword_data + source_data[offset+len(dword_data):] )
        else:
            return False
        return newdata
    def ROL(self,data, shift):
        size = 32
        shift %= size
        remains = data >> (size - shift)
        body = (data << shift) - (remains << size )
        return (body + remains)
    def ROR(self,data, shift):
        size = 32
        shift %= size
        body = data >> shift
        remains = (data << (size - shift)) - (body << size)
        return (body + remains)

    def SchemaCipher(self,data,index,schema):
        for cursor in schema:
            if cursor.OP == "XOR":
                print("XOR: {}".format(hex(int.from_bytes(data[index:index+4], "little"))))  
                value = int.from_bytes(data[index:index+4], "little") ^ int.from_bytes(cursor.Key, "little")
                value_byte = value.to_bytes(4,"little")
                data = self.set_dword_offset(bytes(data),value_byte,index)
            elif cursor.OP == "ADD":
                print("ADD: {}".format(hex(int.from_bytes(data[index:index+4], "little"))))
                value = (int.from_bytes(data[index:index+4], "little") - int.from_bytes(cursor.Key, "little")) 
                value_byte = value.to_bytes(4,"little")
                data = self.set_dword_offset(bytes(data),value_byte,index)
            elif cursor.OP == "SUB":
                print("SUB: {}".format(hex(int.from_bytes(data[index:index+4], "little"))))
                value = (int.from_bytes(data[index:index+4], "little") + int.from_bytes(cursor.Key, "little")) 
                value_byte = value.to_bytes(4,"little")
                data = self.set_dword_offset(bytes(data),value_byte,index)
            elif cursor.OP == "ROL":
                print("ROL: {}".format(hex(int.from_bytes(data[index:index+4], "little"))))
                value = self.ROR(int.from_bytes(data[index:index+4], "little"),int.from_bytes(cursor.Key, "little"))
                #value = (int.from_bytes(data[index:index+4], "little") + int.from_bytes(cursor.Key, "little")) 
                value_byte = value.to_bytes(4,"little")
                data = self.set_dword_offset(bytes(data),value_byte,index)

            elif cursor.OP == "ROR":
                print("ROR: {}".format(hex(int.from_bytes(data[index:index+4], "little"))))
                value = self.ROL(int.from_bytes(data[index:index+4], "little"),int.from_bytes(cursor.Key, "little"))
                #value = (int.from_bytes(data[index:index+4], "little") + int.from_bytes(cursor.Key, "little")) 
                value_byte = value.to_bytes(4,"little")
                data = self.set_dword_offset(bytes(data),value_byte,index)

            elif cursor.OP == "NOT":
                print("NOT: {}".format(hex(int.from_bytes(data[index:index+4], "little"))))
                value = (~int.from_bytes(data[index:index+4], "little")) &0xffffffff
                value_byte = value.to_bytes(4,"little")
                data = self.set_dword_offset(bytes(data),value_byte,index)
            else:
                SetError("SchemaCipher cursor.OP Error")
            index += 4
        return bytes(data)

    def AddCallOver(self, payload) :

        # Perform a shport call over the payload
        #call = "mov {0},{1}; call {0};".format(GetRandomRegister(self.arch),hex(len(payload)+5))
        call = "call {};".format(hex(len(payload)+5))
        callBin, ok = Assemble(self.arch,call)
        if ok == 0:
            SetError("call-over assembly failed")

        payload  = bytes(callBin) + payload
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
            pop,_ = Assemble(self.arch,"POP {};".format(reg))  # !!
            payload =   payload + bytes(pop)

        else :
            mov,_ = Assemble(self.arch,"MOV {},[{}];".format(reg, self.GetStackPointer()) )
            sub,_ = Assemble(self.arch,"SUB {},{};".format( self.GetStackPointer(), hex(int(self.arch/8))) )
            payload = payload + bytes(mov) + bytes(sub)

        for  cursor in schema :

            # Mandatory obfuscation with coin flip for true polimorphism
            garbage = self.GenerateGarbageInstructions()
            
            payload = payload + garbage

            stepAssembly = ""

            if cursor.Key == None:
                stepAssembly += "\t{} DWORD PTR [{}+{}];\n".format(cursor.OP, reg, hex(index))
            else :
                stepAssembly +="\t{} DWORD PTR [{}+{}],{};\n".format(cursor.OP, reg, hex(index), hex(int.from_bytes(cursor.Key, "little")))

            #fmt.Println(stepAssembly)
            decipherStep,_ = Assemble(self.arch,stepAssembly)

            payload = payload + bytes(decipherStep)
            index += 4

        # More possibilities...
        returnAssembly = ""
        if self.CoinFlip():
            returnAssembly = "jmp {};".format(reg)
        else :
            returnAssembly = "push {};ret;".format(reg)


        returnInstruction,_ = Assemble(self.arch,returnAssembly)

        garbage = self.GenerateGarbageInstructions()

        payload = payload + bytes(returnInstruction) + bytes(garbage)

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
