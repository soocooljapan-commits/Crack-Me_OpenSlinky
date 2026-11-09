import struct
import sys
from unicorn import *
from unicorn.x86_const import *
from pe import d, secs, r2o, parse_imports

BASE = 0x180000000
STACK = 0x200000000
STUB = 0x300000000

imps = parse_imports()

mu = Uc(UC_ARCH_X86, UC_MODE_64)


def align(x, a=0x1000):
    return (x + a - 1) & ~(a - 1)


# map image
for name, va, vs, ro, rs in secs:
    if rs == 0:
        continue
    start = BASE + va
    size = align(max(vs, rs))
    mu.mem_map(start, size)
    data = d[ro:ro + rs]
    mu.mem_write(start, data)

mu.mem_map(STACK, 0x200000)
mu.mem_map(STUB, 0x200000)

# build stubs
stub_names = {}
for i, (iat, nm) in enumerate(sorted(imps.items())):
    addr = STUB + i * 16
    stub_names[addr] = nm
    # ret
    mu.mem_write(addr, b'\xc3')

# patch IAT
for iat, nm in imps.items():
    addr = STUB + sorted(imps.keys()).index(iat) * 16
    mu.mem_write(BASE + iat, struct.pack('<Q', addr))

SP = STACK + 0x100000
KEY = STACK + 0x180000

calls = []


def hook_code(mu, address, size, user):
    if STUB <= address < STUB + 0x200000:
        idx = (address - STUB) // 16
        nm = stub_names.get(address, '?')
        rsp = mu.reg_read(UC_X86_REG_RSP)
        ret = struct.unpack('<Q', mu.mem_read(rsp, 8))[0]
        args = [mu.reg_read(r) for r in (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9)]
        calls.append((nm, args, ret))
        print('CALL %-50s rcx=%x rdx=%x r8=%x r9=%x ret=%x' % (nm, *args, ret))
        mu.reg_write(UC_X86_REG_RAX, 0)
        mu.reg_write(UC_X86_REG_RSP, rsp + 8)
        mu.reg_write(UC_X86_REG_RIP, ret)
        return


mu.hook_add(UC_HOOK_CODE, hook_code)

key = sys.argv[1] if len(sys.argv) > 1 else 'A' * 32
wkey = key.encode('utf-16-le') + b'\x00\x00'
mu.mem_write(KEY, wkey)

mu.reg_write(UC_X86_REG_RSP, SP)
mu.reg_write(UC_X86_REG_RCX, KEY)
# shadow space
mu.reg_write(UC_X86_REG_RSP, SP - 0x40)
mu.mem_write(SP - 0x40, struct.pack('<Q', 0xdeadbeef))  # return address sentinel

try:
    mu.emu_start(BASE + 0x1000, 0xdeadbeef, count=2000000)
except UcError as e:
    print('UC ERROR', e, 'pc=%x' % mu.reg_read(UC_X86_REG_RIP))
print('done, calls', len(calls))
