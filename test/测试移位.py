def ROL(data, shift,size=32):
    shift %= size
    remains = data >> (size - shift)
    body = (data << shift) - (remains << size )
    return (body + remains)
def ROR(data, shift,size=32):
    shift %= size
    body = data >> shift
    remains = (data << (size - shift)) - (body << size)
    return (body + remains)

rol = ROL(0x11223344,0x55)
ror = ROR(0x11223344,0x55)
covbac = ROR(rol,0x55)

print("rol:{}\nror:{}\ncovbak:{}".format(hex(rol),hex(ror),hex(covbac)))

