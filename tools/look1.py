import struct, hashlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

rt = open('text_runtime.bin', 'rb').read()
dv = open('unpacked/lib_beta_win_unpacked.devirt.bin', 'rb').read()


def secs(d):
    e = struct.unpack_from('<I', d, 0x3c)[0]
    nsec = struct.unpack_from('<H', d, e + 6)[0]
    optsz = struct.unpack_from('<H', d, e + 20)[0]
    o = e + 24 + optsz
    out = {}
    for i in range(nsec):
        p = o + i * 40
        name = d[p:p + 8].rstrip(b'\x00').decode('latin1')
        vs, va, rs, ro = struct.unpack_from('<IIII', d, p + 8)
        out[name] = (va, vs, ro, rs)
    return out, e, o, optsz


sd, e, o, optsz = secs(dv)


def r2o(d, s, rva):
    for n, (va, vs, ro, rs) in s.items():
        if va <= rva < va + max(vs, rs):
            return ro + (rva - va)
    return None


# imports
imp_rva, imp_size = struct.unpack_from('<II', dv, e + 24 + 112 + 8)
print('import dir rva %x size %x' % (imp_rva, imp_size))
off = r2o(dv, sd, imp_rva)
dlls = []
i = 0
while off is not None:
    ent = dv[off + i * 20: off + i * 20 + 20]
    if len(ent) < 20 or ent == b'\x00' * 20:
        break
    oft, ts, fc, name_rva, ft = struct.unpack('<IIIII', ent)
    no = r2o(dv, sd, name_rva)
    nm = dv[no:dv.index(b'\x00', no)].decode('latin1') if no else '?'
    dlls.append(nm)
    i += 1
print('IMPORT DLLS:', dlls)

# disasm
md = Cs(CS_ARCH_X86, CS_MODE_64)
print('== 0x1000..0x1240 ==')
for ins in md.disasm(rt[0x1000:0x1240], 0x1000):
    print('%08x  %-24s %s %s' % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))

print('== rdata 0x140000..0x140200 ==')
blob = rt[0x140000:0x140200]
for i in range(0, len(blob), 16):
    chunk = blob[i:i + 16]
    asc = ''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk)
    print('%08x  %-47s  %s' % (0x140000 + i, chunk.hex(), asc))

print('== hash tests ==')
blob16 = rt[0x140064:0x140074]
print('blob16', blob16.hex())
for key in ('ABCDEFGHIJKLMNOPQRSTUVWXYZ012345', 'A' * 32, 'slinky', ''):
    kb = key.encode()
    for data, tag in ((kb, 'key'), (kb + b'slinky', 'key+slinky'), (b'slinky' + kb, 'slinky+key'),
                      (kb + b'\x00', 'key0'), (kb.lower(), 'key.lower')):
        for alg in ('md5', 'sha1', 'sha256'):
            h = getattr(hashlib, alg)(data).digest()
            if h[:16] == blob16 or h == blob16:
                print('MATCH', tag, alg, key)
print('md5 slinky', hashlib.md5(b'slinky').hexdigest())
