import struct, hashlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

rt = open('text_runtime.bin', 'rb').read()
dv = open('unpacked/lib_beta_win_unpacked.devirt.bin', 'rb').read()


def secs(data):
    e = struct.unpack_from('<I', data, 0x3c)[0]
    nsec = struct.unpack_from('<H', data, e + 6)[0]
    optsz = struct.unpack_from('<H', data, e + 20)[0]
    opt = e + 24
    o = opt + optsz
    out = {}
    for i in range(nsec):
        p = o + i * 40
        name = data[p:p + 8].rstrip(b'\x00').decode('latin1')
        vs, va, rs, ro = struct.unpack_from('<IIII', data, p + 8)
        out[name] = (va, vs, ro, rs)
    return out


sr = secs(rt)
sd = secs(dv)
for n in sr:
    if n not in sd:
        continue
    va, vs, ro, rs = sr[n]
    a = rt[va:va + rs] if rs else b''
    b = dv[sd[n][2]:sd[n][2] + sd[n][3]] if sd[n][3] else b''
    same = hashlib.md5(a).hexdigest() == hashlib.md5(b).hexdigest()
    print('%-9s %s %s' % (n, 'SAME' if same else 'DIFF', hashlib.md5(a).hexdigest()))

va = sr['.text'][0]
code = rt[va:va + 0x1200]
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
for ins in md.disasm(code, va):
    print('%08x  %-24s %s %s' % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
    if ins.address > 0x11a0:
        break
