import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

path = sys.argv[1]
start = int(sys.argv[2], 16)
n = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0x200
d = open(path, 'rb').read()
md = Cs(CS_ARCH_X86, CS_MODE_64)
for ins in md.disasm(d[start:start + n], start):
    print('%08x  %-26s %s %s' % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
