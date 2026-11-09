import struct

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
lo, hi = 0x140000, 0x142200
hits = []
for i in range(0, len(code) - 4):
    v = struct.unpack_from('<i', code, i)[0]
    tgt = va + i + 4 + v
    if lo <= tgt < hi:
        hits.append((va + i, tgt))
print('hits', len(hits))
seen = {}
for a, t in hits:
    seen.setdefault(t, []).append(a)
for t in sorted(seen):
    print('%08x' % t, [hex(x) for x in seen[t][:10]])
