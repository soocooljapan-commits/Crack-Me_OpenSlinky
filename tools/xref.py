import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

d = open('solution/module_dump.bin', 'rb').read()
e = struct.unpack_from('<I', d, 0x3c)[0]
n = struct.unpack_from('<H', d, e + 6)[0]
osz = struct.unpack_from('<H', d, e + 20)[0]
so = e + 24 + osz
secs = []
for i in range(n):
    p = so + i * 40
    nm = d[p:p + 8].rstrip(b'\x00').decode('latin1')
    vs, va, rs, ro = struct.unpack_from('<IIII', d, p + 8)
    secs.append((nm, va, vs, rs))

print('--- sections (dump: offset == rva) ---')
for nm, va, vs, rs in secs:
    print('%-10s va=%08x vs=%08x' % (nm, va, vs))

text = [s for s in secs if s[0] == '.text'][0]
tva, tvs = text[1], text[2]

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

targets = {}
for a in sys.argv[1:]:
    targets[int(a, 16)] = []

code = d[tva:tva + tvs]
for ins in md.disasm(code, tva):
    for op in ins.operands:
        if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
            tgt = ins.address + ins.size + op.mem.disp
            if tgt in targets:
                targets[tgt].append((ins.address, ins.mnemonic, ins.op_str))
        elif op.type == X86_OP_IMM:
            v = op.imm
            if v in targets:
                targets[v].append((ins.address, ins.mnemonic, ins.op_str))

for t, hits in targets.items():
    print()
    print('=== xrefs to %08x (%d) ===' % (t, len(hits)))
    for a, m, o in hits:
        print('  %08x  %-8s %s' % (a, m, o))
