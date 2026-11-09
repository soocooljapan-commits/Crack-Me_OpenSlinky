import struct, sys

SRC = sys.argv[1] if len(sys.argv) > 1 else 'packed.dll'
DST = sys.argv[2] if len(sys.argv) > 2 else 'lib_beta_win_cave.dll'

d = bytearray(open(SRC, 'rb').read())
e = struct.unpack_from('<I', d, 0x3c)[0]
nsec = struct.unpack_from('<H', d, e + 6)[0]
optsz = struct.unpack_from('<H', d, e + 20)[0]
opt = e + 24
sectab = opt + optsz
sections = []
for i in range(nsec):
    p = sectab + i * 40
    nm = bytes(d[p:p + 8]).rstrip(b'\x00').decode('latin1')
    vs, va, rs, ro = struct.unpack_from('<IIII', d, p + 8)
    sections.append((nm, va, vs, ro, rs))


def r2o(rva):
    for nm, va, vs, ro, rs in sections:
        if va <= rva < va + max(vs, rs):
            return ro + (rva - va)
    return None


exp_rva, exp_sz = struct.unpack_from('<II', d, opt + 112)
eo = r2o(exp_rva)
(chars, ts, maj, mnr, name_rva, ord_base, naddr, nnames, aor, anr, aord) = struct.unpack_from('<IIHHIIIIIII', d, eo)
print('naddr', naddr, 'nnames', nnames)
for i in range(nnames):
    nr = struct.unpack_from('<I', d, r2o(anr) + i * 4)[0]
    no = r2o(nr)
    nm = bytes(d[no:d.index(b'\x00', no)]).decode('latin1')
    ordv = struct.unpack_from('<H', d, r2o(aord) + i * 2)[0]
    fa = r2o(aor) + ordv * 4
    print(' ', nm, 'rva', hex(struct.unpack_from('<I', d, fa)[0]))
    if nm == 'slinky_init':
        target = fa

# code cave: end of .slinky2 virtual size, inside mapped section, executable
for nm, va, vs, ro, rs in sections:
    if nm == '.slinky2':
        cave_rva = va + vs
        cave_off = ro + vs
        print('cave rva %x off %x' % (cave_rva, cave_off))
        print('cave bytes', bytes(d[cave_off:cave_off + 32]).hex())
        d[cave_off:cave_off + 3] = b'\x31\xc0\xc3'
struct.pack_into('<I', d, target, cave_rva)
open(DST, 'wb').write(d)
print('wrote', DST, 'export ->', hex(cave_rva))
