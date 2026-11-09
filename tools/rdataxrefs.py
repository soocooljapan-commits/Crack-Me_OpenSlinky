import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM, CS_OP_IMM

path = 'unpacked/lib_beta_win_unpacked.devirt.bin'
d = open(path, 'rb').read()
e = struct.unpack_from('<I', d, 0x3c)[0]
nsec = struct.unpack_from('<H', d, e + 6)[0]
optsz = struct.unpack_from('<H', d, e + 20)[0]
o = e + 24 + optsz
secs = {}
for i in range(nsec):
    p = o + i * 40
    name = d[p:p + 8].rstrip(b'\x00').decode('latin1')
    vs, va, rs, ro = struct.unpack_from('<IIII', d, p + 8)
    secs[name] = (va, vs, ro, rs)

va, vs, ro, rs = secs['.text']
code = d[ro:ro + rs]
base = 0x180000000
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

lo, hi = 0x140000, 0x142200
hits = []
for ins in md.disasm(code, base + va):
    if ins.mnemonic == 'lea' and len(ins.operands) == 2:
        op = ins.operands[1]
        if op.type == CS_OP_MEM and op.mem.base == 0 and op.mem.index == 0:
            tgt = ins.address + ins.size + op.mem.disp
            rva = tgt - base
            if lo <= rva < hi:
                hits.append((ins.address - base, rva, ins.mnemonic + ' ' + ins.op_str))

print('hits', len(hits))
for a, t, s in hits:
    # string preview
    for n, (v, vsz, r, rsz) in secs.items():
        if v <= t < v + max(vsz, rsz):
            off = r + (t - v)
            raw = d[off:off + 48]
            prev = raw.split(b'\x00')[0]
            txt = ''.join(chr(c) if 32 <= c < 127 else '.' for c in prev)
            break
    else:
        txt = ''
    print('%08x -> %08x  %-30s %s' % (a, t, s, txt))
