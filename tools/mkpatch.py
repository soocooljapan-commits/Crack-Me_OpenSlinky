import struct, shutil, os, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

SRC = 'unpacked/lib_beta_win_unpacked.devirt.bin'
DST = 'devirt_patched.dll'
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

print('entry', hex(struct.unpack_from('<I', d, opt + 16)[0]))
# export dir
exp_rva, exp_sz = struct.unpack_from('<II', d, opt + 112)
print('export dir', hex(exp_rva), hex(exp_sz))
# tls dir
tls_rva, tls_sz = struct.unpack_from('<II', d, opt + 112 + 9 * 8)
print('tls dir', hex(tls_rva), hex(tls_sz))


def r2o(rva):
    for n, va, vs, ro, rs in secs:
        if va <= rva < va + max(vs, rs):
            return ro + (rva - va)
    return None


def read(rva, n):
    off = r2o(rva)
    return bytes(d[off:off + n]) if off is not None else b''


if exp_rva:
    off = r2o(exp_rva)
    chars, ts, maj, mnr, name_rva, ordbase, naddr, nnames, aor, anr, aord = struct.unpack_from('<IIHHIIIIIII', d, off)
    print('exports', nnames)
    for i in range(nnames):
        nr = struct.unpack_from('<I', d, r2o(anr) + i * 4)[0]
        nm = read(nr, 64).split(b'\x00')[0].decode('latin1')
        ordv = struct.unpack_from('<H', d, r2o(aord) + i * 2)[0]
        frva = struct.unpack_from('<I', d, r2o(aor) + ordv * 4)[0]
        print('  ', nm, hex(frva))

if tls_rva:
    off = r2o(tls_rva)
    (start_raw, end_raw, addr_idx, addr_cb, zero, chars) = struct.unpack_from('<QQQQII', d, off)
    print('tls start', hex(start_raw), 'end', hex(end_raw), 'cb', hex(addr_cb))
    if addr_cb:
        cbo = r2o(addr_cb - 0x180000000) if addr_cb >= 0x180000000 else r2o(addr_cb)
        print('tls cb bytes', bytes(d[cbo:cbo + 32]).hex() if cbo else None)

md = Cs(CS_ARCH_X86, CS_MODE_64)
print('== 0x1220..0x12c0 ==')
for ins in md.disasm(read(0x1220, 0xa0), 0x1220):
    print('%08x  %-24s %s %s' % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))

# patch entry -> 0x1220
struct.pack_into('<I', d, opt + 16, 0x1220)
# disable TLS callbacks
if tls_rva:
    toff = r2o(tls_rva)
    struct.pack_into('<Q', d, toff + 24, 0)
# patch 0x1290 -> xor eax,eax; ret
off = r2o(0x1290)
d[off:off + 3] = b'\x31\xc0\xc3'
open(DST, 'wb').write(d)
print('wrote', DST, os.path.getsize(DST))
