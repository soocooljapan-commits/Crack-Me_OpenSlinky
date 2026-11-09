import struct, re, hashlib
from pe import parse_imports

def parse(path):
    d = open(path, 'rb').read()
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
    return d, secs

def r2o(secs, rva):
    for n, va, vs, ro, rs in secs:
        if va <= rva < va + max(vs, rs):
            return ro + (rva - va)
    return None

dp, sp = parse('lib_beta_win')
dd, sd = parse('unpacked/lib_beta_win_unpacked.devirt.bin')

print('== sections ==')
for name, va, vs, ro, rs in sp:
    b = [s for s in sd if s[0] == name]
    ha = hashlib.md5(dp[ro:ro + rs]).hexdigest() if rs else '-'
    if not b:
        print('%-9s packed %s devirt MISSING' % (name, ha))
        continue
    nb, nva, nvs, nro, nrs = b[0]
    hb = hashlib.md5(dd[nro:nro + nrs]).hexdigest() if nrs else '-'
    print('%-9s packed %s devirt %s %s vs %x/%x' % (name, ha, hb, 'SAME' if ha == hb else 'DIFF', vs, nvs))

print('== rdata 0x140000 ==')
o = r2o(sd, 0x140000)
for i in range(0, 0x1e0, 16):
    b = dd[o + i:o + i + 16]
    print('%08x %s %s' % (0x140000 + i, b.hex(), ''.join(chr(c) if 32 <= c < 127 else '.' for c in b)))

print('== qword table transforms ==')
o = r2o(sd, 0x1400c0)
qs = list(struct.unpack_from('<24Q', dd, o))
for i, q in enumerate(qs):
    print('%02d %016x' % (i, q))
blob = bytes.fromhex('e984c65498462e0bb9877136f4368535')
rep = (blob * 16)[:192]
print('xor blob repeated:')
for i, q in enumerate(qs):
    x = q ^ struct.unpack_from('<Q', rep, i * 8)[0]
    print('%02d %016x %s' % (i, x, ''.join(chr(c) if 32 <= c < 127 else '.' for c in x.to_bytes(8, 'little'))))

print('== immediate searches in devirt ==')
for label, pat in [
    ('mov eax,0x3e8', b'\xb8\xe8\x03\x00\x00'),
    ('mov rax,0x3e8', b'\x48\xc7\xc0\xe8\x03\x00\x00'),
    ('mov r32,0x3e8', b'\x41\xb8\xe8\x03\x00\x00'),
    ('qword 0x20000001028', struct.pack('<Q', 0x20000001028)),
    ('qword 0x20000001000', struct.pack('<Q', 0x20000001000)),
    ('qword 0x20000000000', struct.pack('<Q', 0x20000000000)),
]:
    hits = []
    i = 0
    while True:
        i = dd.find(pat, i)
        if i < 0:
            break
        hits.append(i)
        i += 1
    print(label, len(hits), [hex(h) for h in hits[:12]])

print('== packed same immediates ==')
for label, pat in [
    ('mov eax,0x3e8', b'\xb8\xe8\x03\x00\x00'),
    ('qword 0x20000001028', struct.pack('<Q', 0x20000001028)),
    ('qword 0x20000001000', struct.pack('<Q', 0x20000001000)),
]:
    hits = []
    i = 0
    while True:
        i = dp.find(pat, i)
        if i < 0:
            break
        hits.append(i)
        i += 1
    print(label, len(hits), [hex(h) for h in hits[:12]])

print('== ascii around devirt file off 0x26f847a ==')
print(''.join(chr(c) if 32 <= c < 127 else '.' for c in dd[0x26f847a - 100:0x26f847a + 400]))

print('== PEM ==')
for m in re.finditer(rb'-----BEGIN [A-Z ]+-----', dd):
    print(hex(m.start()), m.group().decode())

print('== IAT calls in .vdvrt / .slinky0 / .text ==')
imps = parse_imports()
for secname in ('.vdvrt', '.slinky0', '.text'):
    s = [x for x in sd if x[0] == secname]
    if not s:
        continue
    _, va, vs, ro, rs = s[0]
    data = dd[ro:ro + rs]
    found = []
    for m in re.finditer(b'\xff[\x15\x25]', data):
        addr = va + m.start()
        disp = struct.unpack_from('<i', data, m.start() + 2)[0]
        tgt = addr + 6 + disp
        nm = imps.get(tgt)
        if nm:
            found.append((addr, nm, data[m.start() + 1]))
    print(secname, len(found))
    for addr, nm, op in found[:60]:
        print('  %08x %s %s' % (addr, 'call' if op == 0x15 else 'jmp', nm))

print('== DB address/name pairs ==')
db = open('unpacked/lib_beta_win_unpacked.devirt.bin.i64', 'rb').read()

def dbctx(off, n=100):
    lo = max(0, off - n)
    hi = off + n
    return ''.join(chr(c) if 32 <= c < 127 else '.' for c in db[lo:hi])

for addr in (0x180001000, 0x180001290, 0x1800010f0, 0x180001220, 0x180a6f4d2):
    pat = struct.pack('<Q', addr)
    hits = []
    i = 0
    while True:
        i = db.find(pat, i)
        if i < 0:
            break
        hits.append(i)
        i += 1
    print('db addr', hex(addr), len(hits), [hex(h) for h in hits[:8]])
    for h in hits[:3]:
        print('   ', dbctx(h, 70))

for pat in (b'notepad', b'Notepad', b'NOTEPAD'):
    hits = []
    i = 0
    while True:
        i = db.find(pat, i)
        if i < 0:
            break
        hits.append(i)
        i += 1
    print(pat, [hex(h) for h in hits[:8]])
