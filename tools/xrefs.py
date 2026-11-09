import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

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


_, text_va, text_vs, text_ro, text_rs = [s for s in secs if s[0] == '.text'][0]
code = d[text_ro:text_ro + text_vs]

targets = {
    0x14090b: 'JNI_GetCreatedJavaVMs',
    0x140a80: 'SlinkyChannelHandler',
    0x140a95: '<init>',
    0x140aa0: 'packet_handler',
    0x140064: 'blob16',
    0x140075: 'slinky',
    0x140098: 'Authentication failed',
    0x140023: 'Invalid license key',
    0x140038: 'status: %lu',
}

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
hits = {k: [] for k in targets}

for ins in md.disasm(code, text_va):
    for op in ins.operands:
        if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
            tgt = ins.address + ins.size + op.mem.disp
            if tgt in hits:
                hits[tgt].append((ins.address, ins.mnemonic, ins.op_str))

for t, name in targets.items():
    print('%08x %-24s %d' % (t, name, len(hits[t])))
    for a, m, o in hits[t][:12]:
        print('    %08x  %s %s' % (a, m, o))
