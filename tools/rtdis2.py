import struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

rt = open('text_runtime.bin', 'rb').read()
start = int(sys.argv[1], 16)
n = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x300
base = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
for ins in md.disasm(rt[start:start + n], start + base):
    print('%08x  %-26s %s %s' % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
