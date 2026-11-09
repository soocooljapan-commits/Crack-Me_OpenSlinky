import struct, sys

def pe_checksum(data, checksum_off):
    # standard PE image checksum
    total = 0
    n = len(data)
    i = 0
    while i + 1 < n:
        if i == checksum_off:
            w = 0
        else:
            w = data[i] | (data[i + 1] << 8)
        total += w
        total = (total & 0xffff) + (total >> 16)
        i += 2
    if i < n:
        total += data[i]
        total = (total & 0xffff) + (total >> 16)
    total = (total & 0xffff) + (total >> 16)
    return (total + n) & 0xffffffff


SRC = sys.argv[1]
DST = sys.argv[2]
d = bytearray(open(SRC, 'rb').read())
e = struct.unpack_from('<I', d, 0x3c)[0]
opt = e + 24
ck_off = opt + 64
struct.pack_into('<I', d, ck_off, 0)
ck = pe_checksum(d, ck_off)
struct.pack_into('<I', d, ck_off, ck)
open(DST, 'wb').write(d)
print('checksum %08x written to %s' % (ck, DST))
