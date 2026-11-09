import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

path = 'solution/module_dump.bin'
d = open(path, 'rb').read()

start = int(sys.argv[1], 16)
end = int(sys.argv[2], 16)
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
code = d[start:end]
for ins in md.disasm(code, start):
    line = '%08x  %-8s %s' % (ins.address, ins.mnemonic, ins.op_str)
    if ins.mnemonic in ('call', 'jmp') and ins.op_str.startswith('0x'):
        try:
            t = int(ins.op_str, 16)
            if 0x1000 <= t < 0x140000:
                line += '   ; -> %08x' % t
        except ValueError:
            pass
    print(line)
