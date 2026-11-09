import ctypes, struct, sys, os
from ctypes import wintypes

PATH = sys.argv[1] if len(sys.argv) > 1 else 'unpacked/lib_beta_win_unpacked.devirt.bin'
KEY = sys.argv[2] if len(sys.argv) > 2 else 'A' * 32

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.VirtualAlloc.restype = ctypes.c_void_p
k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
k32.LoadLibraryW.restype = ctypes.c_void_p
k32.LoadLibraryW.argtypes = [wintypes.LPCWSTR]
k32.GetProcAddress.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]


class EXCEPTION_RECORD(ctypes.Structure):
    pass


EXCEPTION_RECORD._fields_ = [
    ('ExceptionCode', wintypes.DWORD), ('ExceptionFlags', wintypes.DWORD),
    ('ExceptionRecord', ctypes.POINTER(EXCEPTION_RECORD)), ('ExceptionAddress', ctypes.c_void_p),
    ('NumberParameters', wintypes.DWORD), ('ExceptionInformation', ctypes.c_void_p * 15)]


class CONTEXT(ctypes.Structure):
    _fields_ = [('P1Home', ctypes.c_uint64), ('P2Home', ctypes.c_uint64), ('P3Home', ctypes.c_uint64),
                ('P4Home', ctypes.c_uint64), ('P5Home', ctypes.c_uint64), ('P6Home', ctypes.c_uint64),
                ('ContextFlags', wintypes.DWORD), ('MxCsr', wintypes.DWORD),
                ('SegCs', wintypes.WORD), ('SegDs', wintypes.WORD), ('SegEs', wintypes.WORD),
                ('SegFs', wintypes.WORD), ('SegGs', wintypes.WORD), ('SegSs', wintypes.WORD),
                ('EFlags', wintypes.DWORD),
                ('Dr0', ctypes.c_uint64), ('Dr1', ctypes.c_uint64), ('Dr2', ctypes.c_uint64), ('Dr3', ctypes.c_uint64),
                ('Dr6', ctypes.c_uint64), ('Dr7', ctypes.c_uint64),
                ('Rax', ctypes.c_uint64), ('Rcx', ctypes.c_uint64), ('Rdx', ctypes.c_uint64), ('Rbx', ctypes.c_uint64),
                ('Rsp', ctypes.c_uint64), ('Rbp', ctypes.c_uint64), ('Rsi', ctypes.c_uint64), ('Rdi', ctypes.c_uint64),
                ('R8', ctypes.c_uint64), ('R9', ctypes.c_uint64), ('R10', ctypes.c_uint64), ('R11', ctypes.c_uint64),
                ('R12', ctypes.c_uint64), ('R13', ctypes.c_uint64), ('R14', ctypes.c_uint64), ('R15', ctypes.c_uint64),
                ('Rip', ctypes.c_uint64)]


class EXCEPTION_POINTERS(ctypes.Structure):
    _fields_ = [('ExceptionRecord', ctypes.POINTER(EXCEPTION_RECORD)), ('ContextRecord', ctypes.POINTER(CONTEXT))]


alloc_log = []
seen = {}


@ctypes.WINFUNCTYPE(wintypes.LONG, ctypes.POINTER(EXCEPTION_POINTERS))
def veh(info):
    rec = info.contents.ExceptionRecord.contents
    ctx = info.contents.ContextRecord.contents
    code = rec.ExceptionCode
    addr = 0
    if rec.NumberParameters >= 2:
        addr = rec.ExceptionInformation[1] or 0
    if code == 0xC0000005 and addr >= 0x10000:
        key = (addr, ctx.Rip)
        seen[key] = seen.get(key, 0) + 1
        if seen[key] > 3:
            print('LOOP at %x rip %x' % (addr, ctx.Rip), flush=True)
            os._exit(4)
        base = addr & ~0xFFFF
        r = k32.VirtualAlloc(ctypes.c_void_p(base), 0x10000, 0x3000, 0x40)
        if r:
            alloc_log.append((addr, r))
            if len(alloc_log) < 300:
                print('FAULT %x -> alloc %x rip=%x' % (addr, r, ctx.Rip), flush=True)
            return -1
    print('UNHANDLED code=%08x addr=%x rip=%x' % (code, addr, ctx.Rip), flush=True)
    print(' rax=%x rbx=%x rcx=%x rdx=%x rsi=%x rdi=%x rbp=%x rsp=%x' % (
        ctx.Rax, ctx.Rbx, ctx.Rcx, ctx.Rdx, ctx.Rsi, ctx.Rdi, ctx.Rbp, ctx.Rsp), flush=True)
    print(' r8=%x r9=%x r10=%x r11=%x r12=%x r13=%x r14=%x r15=%x' % (
        ctx.R8, ctx.R9, ctx.R10, ctx.R11, ctx.R12, ctx.R13, ctx.R14, ctx.R15), flush=True)
    os._exit(3)


k32.AddVectoredExceptionHandler(1, veh)

pm = k32.VirtualAlloc(ctypes.c_void_p(0x20000000000), 0x10000000, 0x3000, 0x40)
print('premap', hex(pm or 0), flush=True)

data = open(PATH, 'rb').read()
e = struct.unpack_from('<I', data, 0x3c)[0]
nsec = struct.unpack_from('<H', data, e + 6)[0]
optsz = struct.unpack_from('<H', data, e + 20)[0]
opt = e + 24
secoff = opt + optsz
sizehdr = struct.unpack_from('<I', data, opt + 60)[0]
sizeimg = struct.unpack_from('<I', data, opt + 56)[0]
imgbase = struct.unpack_from('<Q', data, opt + 24)[0]
secs = []
for i in range(nsec):
    o = secoff + i * 40
    name = data[o:o + 8].rstrip(b'\x00').decode('latin1')
    vs, va, rs, ro = struct.unpack_from('<IIII', data, o + 8)
    secs.append((name, va, vs, ro, rs))


def r2o(rva):
    for n, va, vs, ro, rs in secs:
        if va <= rva < va + max(vs, rs):
            return ro + (rva - va)
    return None


def cstr(rva):
    o = r2o(rva)
    end = data.index(b'\x00', o)
    return data[o:end].decode('latin1', 'replace')


mem = k32.VirtualAlloc(ctypes.c_void_p(imgbase), sizeimg, 0x3000, 0x40)
print('image', hex(mem or 0), 'want', hex(imgbase), flush=True)
ctypes.memmove(mem, data[:sizehdr], sizehdr)
for name, va, vs, ro, rs in secs:
    if rs:
        ctypes.memmove(mem + va, data[ro:ro + rs], rs)

imp_rva, imp_sz = struct.unpack_from('<II', data, opt + 120)
o = r2o(imp_rva)
i = 0
while True:
    ilt, ts, fc, nrva, iat = struct.unpack_from('<IIIII', data, o + i * 20)
    if ilt == 0 and nrva == 0 and fc == 0:
        break
    dllname = cstr(nrva)
    h = k32.LoadLibraryW(dllname)
    t = ilt or iat
    j = 0
    while True:
        v = struct.unpack_from('<Q', data, r2o(t) + 8 * j)[0]
        if v == 0:
            break
        addr = None
        if not (v >> 63):
            addr = k32.GetProcAddress(h, cstr((v & 0x7fffffff) + 2).encode())
        if addr:
            ctypes.c_uint64.from_address(mem + iat + 8 * j).value = addr
        j += 1
    i += 1

keybuf = ctypes.create_unicode_buffer(KEY)
FN = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_wchar_p)
fn = FN(mem + 0x1000)
print('calling', flush=True)
r = fn(keybuf)
print('RET', r, hex(r & 0xffffffff), 'faults', len(alloc_log), flush=True)
