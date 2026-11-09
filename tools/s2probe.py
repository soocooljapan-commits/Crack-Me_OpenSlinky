import struct

pk = open('packed.dll', 'rb').read()
rt = open('text_runtime.bin', 'rb').read()

# .slinky2 raw at 0x800, size 0x1e5c400
s2 = pk[0x800:0x800 + 0x1e5c400]
print('slinky2 raw len', hex(len(s2)))

pats = {
    'Invalid license key': b'Invalid license key',
    'status: %lu': b'status: %lu',
    'Authentication failed': b'Authentication failed: %s',
    'SLINKY_LICENSE wide': 'SLINKY_LICENSE'.encode('utf-16-le'),
    '1290 prologue': bytes.fromhex('5541574156415541545657534881ec48060000'),
    '1000 prologue': bytes.fromhex('5556574883ec50488d6c2450'),
    'entry prologue': bytes.fromhex('415249ba1e4f0f6eed5e2e9c9c4981ea37730a5f'),
}
for name, p in pats.items():
    i = s2.find(p)
    print('%-24s %s' % (name, hex(i) if i >= 0 else 'NOT FOUND'))
    if i >= 0:
        print('   ctx', s2[max(0, i - 16):i + 48].hex())

# xor correlation between slinky2 raw and runtime .text
a = s2[:0x400]
b = rt[0x1000:0x1400]
x = bytes(u ^ v for u, v in zip(a, b))
print('xor head', x[:64].hex())
# look for repeating period
for period in (1, 2, 4, 8, 16, 32):
    ok = all(x[i] == x[i % period] for i in range(len(x)))
    print('period', period, ok)
print('most common xor bytes', sorted(set(x), key=x.count, reverse=True)[:8])
