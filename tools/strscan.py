import struct, re

dv = open('unpacked/lib_beta_win_unpacked.devirt.bin', 'rb').read()
rt = open('text_runtime.bin', 'rb').read()


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
    return out


sd = secs(dv)
for name in ('.rdata', '.data', '.slinky1'):
    va, vs, ro, rs = sd[name]
    blob = dv[ro:ro + rs]
    print('==', name, hex(len(blob)))
    for pat in (b'http://', b'https://', b'api.', b'.com', b'.net', b'slinky', b'Sl', b'SLINKY', b'license', b'License', b'auth'):
        for m in re.finditer(re.escape(pat), blob):
            s = max(0, m.start() - 24)
            chunk = blob[s:m.start() + 80]
            txt = ''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk)
            print('  %-10s %08x %s' % (pat.decode(), va + m.start(), txt))
            break

print('== strings in .rdata (>=6) ==')
va, vs, ro, rs = sd['.rdata']
blob = dv[ro:ro + rs]
for m in re.finditer(rb'[\x20-\x7e]{6,}', blob):
    t = m.group().decode()
    if any(k in t.lower() for k in ('http', 'api', 'licen', 'auth', 'slinky', 'key', 'token', 'user', 'pass', 'status', 'error')):
        print('  %08x %s' % (va + m.start(), t[:160]))
