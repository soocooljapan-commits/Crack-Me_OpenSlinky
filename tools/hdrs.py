import struct

for path in ('lib_beta_win', 'unpacked/lib_beta_win_unpacked.devirt.bin'):
    d = open(path, 'rb').read()
    e = struct.unpack_from('<I', d, 0x3c)[0]
    opt = e + 24
    entry = struct.unpack_from('<I', d, opt + 16)[0]
    imgbase = struct.unpack_from('<Q', d, opt + 24)[0]
    print(path, 'entry', hex(entry), 'base', hex(imgbase))
    nsec = struct.unpack_from('<H', d, e + 6)[0]
    optsz = struct.unpack_from('<H', d, e + 20)[0]
    o = opt + optsz
    for i in range(nsec):
        p = o + i * 40
        name = d[p:p + 8].rstrip(b'\x00').decode('latin1')
        vs, va, rs, ro = struct.unpack_from('<IIII', d, p + 8)
        ch = d[p + 36:p + 40]
        print('  %-9s va %08x vs %08x ro %08x rs %08x ch %s' % (name, va, vs, ro, rs, ch.hex()))
