import struct, sys
from capstone import *

PATH = r'unpacked/lib_beta_win_unpacked.devirt.bin'
d = open(PATH, 'rb').read()
e = struct.unpack_from('<I', d, 0x3c)[0]
nsec = struct.unpack_from('<H', d, e + 6)[0]
optsz = struct.unpack_from('<H', d, e + 20)[0]
opt = e + 24
secoff = opt + optsz
secs = []
for i in range(nsec):
    o = secoff + i * 40
    name = d[o:o + 8].rstrip(b'\x00').decode('latin1')
    vs, va, rs, ro = struct.unpack_from('<IIII', d, o + 8)
    secs.append((name, va, vs, ro, rs))


def r2o(rva):
    for n, va, vs, ro, rs in secs:
        if va <= rva < va + max(vs, rs):
            return ro + (rva - va)
    return None


start = int(sys.argv[1], 16)
end = int(sys.argv[2], 16)
md = Cs(CS_ARCH_X86, CS_MODE_64)
o = r2o(start)
code = d[o:r2o(end)]
for ins in md.disasm(code, start):
    print('%08x  %-24s %s %s' % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
