import struct

for path in ('unpacked/lib_beta_win_unpacked.devirt.bin', 'lib_beta_win', 'packed.dll'):
    d = open(path, 'rb').read()
    print('==', path, len(d))
    for val in (0x20000001028, 0x20000001000, 0x20000000000, 0x20000000000 + 0x1028):
        pat = struct.pack('<Q', val)
        hits = []
        i = 0
        while True:
            i = d.find(pat, i)
            if i < 0:
                break
            hits.append(i)
            i += 1
        print('  %x hits %d %s' % (val, len(hits), [hex(h) for h in hits[:10]]))
        for h in hits[:3]:
            lo = max(0, h - 32)
            print('    ', hex(h), d[lo:h + 40].hex())
