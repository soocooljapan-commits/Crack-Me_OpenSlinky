import struct
import re

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


def o2r(o):
    for nm, va, vs, ro, rs in secs:
        if ro <= o < ro + max(rs, 1):
            return va + (o - ro), nm
    return None, None


print('--- sections ---')
for nm, va, vs, ro, rs in secs:
    print('%-10s va=%08x vs=%08x ro=%08x rs=%08x' % (nm, va, vs, ro, rs))

print()
print('--- occurrences of 2b 23 (0x232b LE) ---')
for m in re.finditer(re.escape(b'\x2b\x23'), d):
    rva, nm = o2r(m.start())
    print('%08x file=%08x sec=%s' % (rva or 0, m.start(), nm))

print()
print('--- occurrences of 03 90 (0x9003 BE-ish) ---')
for m in re.finditer(re.escape(b'\x03\x90'), d):
    rva, nm = o2r(m.start())
    print('%08x file=%08x sec=%s' % (rva or 0, m.start(), nm))
