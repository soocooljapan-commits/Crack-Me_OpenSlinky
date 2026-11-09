import struct
import re
import sys

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


keys = ['success', 'valid', 'token', 'expires', 'signature', 'hwid', 'license',
        'error', 'message', 'status', 'data', 'auth', 'sub', 'plan', 'user',
        'device', 'machine', 'key', 'jwt', 'nonce', 'hmac', 'sign']

seen = set()
for m in re.finditer(rb'[ -~]{3,120}', d):
    s = m.group().decode('latin1')
    low = s.lower()
    if not any(k in low for k in keys):
        continue
    if s in seen:
        continue
    seen.add(s)
    print('%08x %s' % (m.start(), s))
