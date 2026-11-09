import struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

d = open('unpacked/lib_beta_win_unpacked.devirt.bin', 'rb').read()
e = struct.unpack_from('<I', d, 0x3c)[0]
n = struct.unpack_from('<H', d, e + 6)[0]
osz = struct.unpack_from('<H', d, e + 20)[0]
so = e + 24 + osz
secs = []
for i in range(n):
    p = so + i * 40
    nm = d[p:p + 8].rstrip(b'\x00').decode('latin1')
    vs, va, rs, ro = struct.unpack_from('<IIII', d, p + 8)
    secs.append((nm, va, vs, ro, rs))


def r2o(rva):
    for nm, va, vs, ro, rs in secs:
        if va <= rva < va + max(vs, rs):
            return ro + (rva - va)
    return None


start = int(sys.argv[1], 16)
end = int(sys.argv[2], 16)
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
o = r2o(start)
code = d[o:o + (end - start)]
for ins in md.disasm(code, start):
    line = '%08x  %-8s %s' % (ins.address, ins.mnemonic, ins.op_str)
    # annotate direct calls/jumps
    if ins.mnemonic in ('call', 'jmp') and ins.op_str.startswith('0x'):
        try:
            t = int(ins.op_str, 16)
            line += '   ; -> %08x' % t
        except ValueError:
            pass
    print(line)
