def set_dword_offset(source_data,dword_data,offset):
    if not isinstance(source_data, bytes):
        raise TypeError('data should be of type: bytes')

    if 0 <= offset < len(source_data):
        newdata = ( source_data[:offset] + dword_data + source_data[offset+len(dword_data):] )
    else:
        return False

    return newdata



Key = b'\x11\xab\x22\x33'
data = b'\x22\x22\x33\x44\x00\x00\x00\x00\x00\x00\x00\x00'

tmp = int.from_bytes(data[0:4], "little") ^ int.from_bytes(Key, "little")

t1 = tmp.to_bytes(4,"little")
new = set_dword_offset(data,t1,0)

print()