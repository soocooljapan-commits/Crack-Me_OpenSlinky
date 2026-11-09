import ctypes, struct, sys
from ctypes import wintypes

PATH = r'C:\Users\user\Pictures\crm\packed.dll'
KEY = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345'
RAW = KEY.encode()

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.VirtualQuery.restype = ctypes.c_size_t
k32.VirtualQuery.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
k32.VirtualProtect.restype = wintypes.BOOL
k32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
k32.VirtualAlloc.restype = ctypes.c_void_p


class MBI(ctypes.Structure):
    _fields_ = [('BaseAddress', ctypes.c_void_p), ('AllocationBase', ctypes.c_void_p),
                ('AllocationProtect', wintypes.DWORD), ('PartitionId', wintypes.WORD),
                ('RegionSize', ctypes.c_size_t), ('State', wintypes.DWORD),
                ('Protect', wintypes.DWORD), ('Type', wintypes.DWORD)]


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


base = None
hits = []
guard_pages = []
rearm = True


@ctypes.WINFUNCTYPE(wintypes.LONG, ctypes.POINTER(EXCEPTION_POINTERS))
def veh(info):
    rec = info.contents.ExceptionRecord.contents
    ctx = info.contents.ContextRecord.contents
    code = rec.ExceptionCode
    if code == 0x80000001:
        addr = rec.ExceptionInformation[1] or 0
        off = (ctx.Rip - base) if base and ctx.Rip >= base else None
        hits.append((ctx.Rip, addr))
        if len(hits) <= 100:
            print('GUARD#%d rip=%x off=%s addr=%x rax=%x rcx=%x rdx=%x rsi=%x rdi=%x r8=%x r9=%x' % (
                len(hits), ctx.Rip, hex(off) if off is not None else '?', addr,
                ctx.Rax, ctx.Rcx, ctx.Rdx, ctx.Rsi, ctx.Rdi, ctx.R8, ctx.R9), flush=True)
        for p in guard_pages:
            old = wintypes.DWORD()
            k32.VirtualProtect(ctypes.c_void_p(p), 0x1000, 0x04, ctypes.byref(old))
        if rearm:
            for p in guard_pages:
                old = wintypes.DWORD()
                k32.VirtualProtect(ctypes.c_void_p(p), 0x1000, 0x04 | 0x100, ctypes.byref(old))
        return -1
    if code == 0xC0000005:
        addr = 0
        if rec.NumberParameters >= 2:
            addr = rec.ExceptionInformation[1] or 0
        off = (ctx.Rip - base) if base and ctx.Rip >= base else None
        print('AV rip=%x off=%s addr=%x' % (ctx.Rip, hex(off) if off is not None else '?', addr), flush=True)
        return -1
    return 0


k32.AddVectoredExceptionHandler(1, veh)

dll = ctypes.CDLL(PATH)
base = ctypes.cast(dll._handle, ctypes.c_void_p).value
print('base', hex(base), flush=True)

FN = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_wchar_p)
print('first 1000', FN(base + 0x1000)(KEY), flush=True)

# find key copies
addr = 0
found = []
while addr < 0x7fffffffffff:
    mbi = MBI()
    q = k32.VirtualQuery(ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
    if not q:
        break
    b = mbi.BaseAddress or 0
    size = mbi.RegionSize
    if mbi.State == 0x1000 and (mbi.Protect & 0xff) in (0x02, 0x04, 0x20, 0x40, 0x80) and size < 0x40000000:
        try:
            data = ctypes.string_at(b, size)
            i = 0
            while True:
                i = data.find(RAW, i)
                if i < 0:
                    break
                found.append(b + i)
                i += 1
        except Exception:
            pass
    addr = b + size

print('found', [hex(x) for x in found], flush=True)
# guard pages of copies
seen = set()
for x in found:
    p = x & ~0xfff
    if p not in seen:
        seen.add(p)
        guard_pages.append(p)

FN2 = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p)
for x in found:
    old = wintypes.DWORD()
    for p in guard_pages:
        k32.VirtualProtect(ctypes.c_void_p(p), 0x1000, 0x04, ctypes.byref(old))
    hits.clear()
    print('calling 1290 with', hex(x), flush=True)
    r = FN2(base + 0x1290)(x)
    print('RET', r, 'hits', len(hits), flush=True)
