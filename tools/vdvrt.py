import struct, re
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

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

va, vs, ro, rs = secs['.vdvrt']
code = d[ro:ro + rs]
print('.vdvrt size', hex(len(code)), 'va', hex(va))

# immediates
for label, pat in [
    ('mov eax,0x3e8', b'\xb8\xe8\x03\x00\x00'),
    ('mov r32,0x3e8', b'\x41\xb8\xe8\x03\x00\x00'),
    ('cmp eax,0x3e8', b'\x3d\xe8\x03\x00\x00'),
    ('cmp r32,0x3e8', b'\x41\x3d\xe8\x03\x00\x00'),
    ('0x3e8 dword', struct.pack('<I', 0x3e8)),
    ('0x20 dword', struct.pack('<I', 0x20)),
    ('0x140064', struct.pack('<I', 0x140064)),
    ('0x140180', struct.pack('<I', 0x140180)),
    ('0x1401a0', struct.pack('<I', 0x1401a0)),
    ('0x1400c0', struct.pack('<I', 0x1400c0)),
    ('0x140064 q', struct.pack('<Q', 0x180140064)),
    ('0x140180 q', struct.pack('<Q', 0x180140180)),
    ('0x1401a0 q', struct.pack('<Q', 0x1801401a0)),
]:
    hits = [m.start() for m in re.finditer(re.escape(pat), code)]
    print(label, len(hits), [hex(va + h) for h in hits[:20]])

# disasm start
md = Cs(CS_ARCH_X86, CS_MODE_64)
print('== head ==')
for ins in md.disasm(code[:0x200], 0x180000000 + va):
    print('%08x %-20s %s %s' % (ins.address - 0x180000000, ins.bytes.hex(), ins.mnemonic, ins.op_str))
