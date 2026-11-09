import struct
from capstone import *

PATH = r'unpacked/lib_beta_win_unpacked.devirt.bin'
d = open(PATH, 'rb').read()
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


def r2o(rva):
    for n, va, vs, ro, rs in secs:
        if va <= rva < va + max(vs, rs):
            return ro + (rva - va)
    return None


def o2r(off):
    for n, va, vs, ro, rs in secs:
        if ro <= off < ro + rs:
            return va + (off - ro)
    return None


targets = {}
for s in [b'Invalid license key', b'Authentication failed: %s', b'API error: status %u',
          b'Failed to load profile', b'Failed to set bind']:
    off = d.find(s)
    if off >= 0:
        rva = o2r(off)
        targets[rva] = s.decode()
        print(s.decode(), hex(off), 'rva', hex(rva))

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
for name, va, vs, ro, rs in secs:
    if name not in ('.text', '.vdvrt'):
        continue
    code = d[ro:ro + rs]
    for ins in md.disasm(code, va):
        if ins.mnemonic == 'lea' and 'rip' in ins.op_str:
            try:
                disp = int(ins.op_str.split('rip + ')[1].split(']')[0], 16)
            except Exception:
                continue
            tgt = ins.address + ins.size + disp
            if tgt in targets:
                print(name, hex(ins.address), ins.mnemonic, ins.op_str, '->', targets[tgt])
