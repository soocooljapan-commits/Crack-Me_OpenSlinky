import struct, re, sys

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


def o2r(off):
    for n, va, vs, ro, rs in secs:
        if ro <= off < ro + rs:
            return va + (off - ro)
    return None


def cstr(rva):
    o = r2o(rva)
    if o is None:
        return None
    end = d.index(b'\x00', o)
    return d[o:end].decode('latin1', 'replace')


def parse_imports():
    imp_rva, imp_sz = struct.unpack_from('<II', d, opt + 120)
    o = r2o(imp_rva)
    i = 0
    out = {}
    while True:
        ilt, ts, fc, nrva, iat = struct.unpack_from('<IIIII', d, o + i * 20)
        if ilt == 0 and nrva == 0 and fc == 0:
            break
        dll = cstr(nrva)
        t = ilt or iat
        j = 0
        while True:
            v = struct.unpack_from('<Q', d, r2o(t) + 8 * j)[0]
            if v == 0:
                break
            if v >> 63:
                nm = 'ord%d' % (v & 0xffff)
            else:
                nm = cstr((v & 0x7fffffff) + 2)
            out[iat + 8 * j] = dll + '!' + nm
            j += 1
        i += 1
    return out


if __name__ == '__main__':
    imps = parse_imports()
    print(len(imps), 'imports')
    for k, v in list(imps.items())[:10]:
        print(hex(k), v)
