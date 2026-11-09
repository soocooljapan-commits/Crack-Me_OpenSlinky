import struct, os, sys

SRC = 'unpacked/lib_beta_win_unpacked.devirt.bin'
DST = sys.argv[1] if len(sys.argv) > 1 else 'devirt_fixed.dll'
PATCH1290 = 'nopatch' not in sys.argv[2:]
KEEPTLS = 'tls' in sys.argv[2:]
FIXED = 'fixed' in sys.argv[2:]

d = bytearray(open(SRC, 'rb').read())
e = struct.unpack_from('<I', d, 0x3c)[0]
nsec = struct.unpack_from('<H', d, e + 6)[0]
optsz = struct.unpack_from('<H', d, e + 20)[0]
opt = e + 24
o = opt + optsz
secs = []
for i in range(nsec):
    p = o + i * 40
    name = bytes(d[p:p + 8]).rstrip(b'\x00').decode('latin1')
    vs, va, rs, ro = struct.unpack_from('<IIII', d, p + 8)
    secs.append((name, va, vs, ro, rs))


def r2o(rva):
    for n, va, vs, ro, rs in secs:
        if va <= rva < va + max(vs, rs):
            return ro + (rva - va)
    return None


struct.pack_into('<I', d, opt + 16, 0x1220)
tls_rva = struct.unpack_from('<I', d, opt + 112 + 9 * 8)[0]
if tls_rva and not KEEPTLS:
    struct.pack_into('<Q', d, r2o(tls_rva) + 24, 0)
if PATCH1290:
    off = r2o(0x1290)
    d[off:off + 3] = b'\x31\xc0\xc3'
if FIXED:
    # clear DYNAMIC_BASE | HIGH_ENTROPY_VA so the image maps at ImageBase 0x180000000
    dch = struct.unpack_from('<H', d, opt + 70)[0]
    struct.pack_into('<H', d, opt + 70, dch & ~0x60)
    # drop the relocation directory: the dumped image is already fixed to 0x180000000
    struct.pack_into('<II', d, opt + 112 + 5 * 8, 0, 0)
open(DST, 'wb').write(d)
print('wrote', DST, 'patch1290', PATCH1290, 'keeptls', KEEPTLS, 'fixed', FIXED)
