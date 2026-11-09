import struct
import sys
from unicorn import *
from unicorn.x86_const import *
from pe import d, secs, parse_imports

BASE = 0x180000000
STACK = 0x200000000
STUB = 0x300000000
imps = parse_imports()

mu = Uc(UC_ARCH_X86, UC_MODE_64)


def align(x, a=0x1000):
    return (x + a - 1) & ~(a - 1)


for name, va, vs, ro, rs in secs:
    if rs == 0:
        continue
    mu.mem_map(BASE + va, align(max(vs, rs)))
    mu.mem_write(BASE + va, d[ro:ro + rs])

mu.mem_map(STACK, 0x400000)
mu.mem_map(STUB, 0x200000)

stub_names = {}
for i, iat in enumerate(sorted(imps.keys())):
    addr = STUB + i * 16
    stub_names[addr] = imps[iat]
    mu.mem_write(addr, b'\xc3')
for iat in imps:
    addr = STUB + sorted(imps.keys()).index(iat) * 16
    mu.mem_write(BASE + iat, struct.pack('<Q', addr))

SP = STACK + 0x200000
KEY = STACK + 0x300000
calls = []
trace = []


def hook_code(mu, address, size, user):
    trace.append((address, size))
    if len(trace) > 400:
        trace.pop(0)
    if STUB <= address < STUB + 0x200000:
        nm = stub_names.get(address, '?')
        rsp = mu.reg_read(UC_X86_REG_RSP)
        ret = struct.unpack('<Q', mu.mem_read(rsp, 8))[0]
        args = [mu.reg_read(r) for r in (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9)]
        calls.append(nm)
        print('CALL %-50s rcx=%x rdx=%x r8=%x r9=%x ret=%x' % (nm, *args, ret))
        mu.reg_write(UC_X86_REG_RAX, 0)
        mu.reg_write(UC_X86_REG_RSP, rsp + 8)
        mu.reg_write(UC_X86_REG_RIP, ret)


mu.hook_add(UC_HOOK_CODE, hook_code)

key = sys.argv[1] if len(sys.argv) > 1 else 'A' * 32
mu.mem_write(KEY, key.encode('utf-16-le') + b'\x00\x00')
mu.reg_write(UC_X86_REG_RSP, SP - 0x40)
mu.mem_write(SP - 0x40, struct.pack('<Q', 0xdeadbeef))
mu.reg_write(UC_X86_REG_RCX, KEY)

try:
    mu.emu_start(BASE + 0x1000, 0xdeadbeef, count=500000)
except UcError as e:
    print('UC ERROR', e, 'pc=%x' % mu.reg_read(UC_X86_REG_RIP))
    for a, s in trace[-40:]:
        print('  %x (%d)' % (a, s))
