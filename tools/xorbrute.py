blobs = {
    '140180': bytes.fromhex('a3a1a4a8adb7be868f95a0acb98b9aaabb899cb0859fb68e'),
    '1401a0': bytes.fromhex('7e737f65667771647c616c707b6367797876607a627d7275'),
    '140064': bytes.fromhex('e984c65498462e0bb9877136f4368535'),
}
for name, b in blobs.items():
    print('===', name, b.hex())
    for k in range(1, 256):
        x = bytes(c ^ k for c in b)
        if all(32 <= c < 127 for c in x):
            print('  xor %02x %s' % (k, x.decode()))
    for key in (b'slinky', b'SLINKY', b'slinkybeta', b'libslinky'):
        x = bytes(c ^ key[i % len(key)] for i, c in enumerate(b))
        if all(32 <= c < 127 for c in x):
            print('  xor %s %s' % (key.decode(), x.decode()))
    for k in range(1, 256):
        x = bytes((c - k) & 0xff for c in b)
        if all(32 <= c < 127 for c in x):
            print('  sub %02x %s' % (k, x.decode()))
    for k in range(1, 256):
        x = bytes((c + k) & 0xff for c in b)
        if all(32 <= c < 127 for c in x):
            print('  add %02x %s' % (k, x.decode()))
