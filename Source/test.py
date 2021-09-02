import encode

with open("./test/shellcode.bin","rb") as f:
    data = f.read()
    enc = encode.Encoder()
    enc.SetArchitecture(32)
    encdata = enc.Encode(data)

f = open("./test/encrypt.bin","wb")
f.write(bytes(encdata))
f.close()

