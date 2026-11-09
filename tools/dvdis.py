import struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

path = 'unpacked/lib_beta_win_unpacked.devirt.bin'
d = open(path, 'rb').read()
e = struct.unpack_from('<I', d, 0x3c)[0]
nsec = struct.unpack_from('<H', d, e + 6)[0]
optsz = struct.unpack_from('<H', d, e + 20)[0]
o = e + 24 + optsz
secs = []
for i in range(nsec):
    p = o + i * 40
    name = d[p:p + 8].rstrip(b'\x00').decode('latin1')
    vs, va, rs, ro = struct.unpack_from('<IIII', d, p + 8)
    secs.append((name, va, vs, ro, rs))


def r2o(rva):
    for n, va, vs, ro, rs in secs:
        if va <= rva < va + max(vs, rs):
            return ro + (rva - va)
    return None


start = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0xa6f480
n = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x120
off = r2o(start)
md = Cs(CS_ARCH_X86, CS_MODE_64)
for ins in md.disasm(d[off:off + n], 0x180000000 + start):
    print('%08x  %-26s %s %s' % (ins.address - 0x180000000, ins.bytes.hex(), ins.mnemonic, ins.op_str))
