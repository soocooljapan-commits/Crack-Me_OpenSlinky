import ctypes, struct, sys, os
from ctypes import wintypes

PATH = r'C:\Users\user\Pictures\crm\packed.dll'
KEY = b'A' * 32

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.VirtualAlloc.restype = ctypes.c_void_p
k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
k32.VirtualProtect.restype = wintypes.BOOL
k32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
k32.VirtualQuery.restype = ctypes.c_size_t
k32.VirtualQuery.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]


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


hits = []
page_addr = None


@ctypes.WINFUNCTYPE(wintypes.LONG, ctypes.POINTER(EXCEPTION_POINTERS))
def veh(info):
    global page_addr
    rec = info.contents.ExceptionRecord.contents
    ctx = info.contents.ContextRecord.contents
    code = rec.ExceptionCode
    if code == 0x80000001:  # guard page
        addr = rec.ExceptionInformation[1] or 0
        hits.append((ctx.Rip, addr))
        print('GUARD rip=%x addr=%x rax=%x rcx=%x rdx=%x rsi=%x rdi=%x' % (
            ctx.Rip, addr, ctx.Rax, ctx.Rcx, ctx.Rdx, ctx.Rsi, ctx.Rdi), flush=True)
        old = wintypes.DWORD()
        k32.VirtualProtect(ctypes.c_void_p(page_addr), 0x1000, 0x04, ctypes.byref(old))
        return -1
    print('EXC %08x rip=%x' % (code, ctx.Rip), flush=True)
    return 0


k32.AddVectoredExceptionHandler(1, veh)

print('loading', PATH, flush=True)
dll = ctypes.CDLL(PATH)
base = ctypes.cast(dll._handle, ctypes.c_void_p).value
print('base', hex(base), flush=True)

page_addr = k32.VirtualAlloc(None, 0x1000, 0x3000, 0x04)
print('page', hex(page_addr), flush=True)
ctypes.memmove(page_addr, KEY, 32)
old = wintypes.DWORD()
k32.VirtualProtect(ctypes.c_void_p(page_addr), 0x1000, 0x04 | 0x100, ctypes.byref(old))

# clear one-shot guard if present
try:
    g = ctypes.c_ubyte.from_address(base + 0x2f9117)
    print('guard byte', g.value, flush=True)
    g.value = 0
except Exception as e:
    print('guard write fail', e, flush=True)

FN = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p)
print('calling 1290', flush=True)
r = FN(base + 0x1290)(page_addr)
print('RET', r, hex(r & 0xffffffff), 'hits', len(hits), flush=True)

for addr in (0x20000000000, 0x20000001000):
    mbi = MBI()
    q = k32.VirtualQuery(ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
    print('vq %x -> %d base=%x size=%x state=%x prot=%x type=%x' % (
        addr, q, mbi.BaseAddress or 0, mbi.RegionSize, mbi.State, mbi.Protect, mbi.Type), flush=True)
    if q and mbi.State == 0x1000:
        size = min(mbi.RegionSize, 0x4000000)
        data = ctypes.string_at(mbi.BaseAddress, size)
        fn = 'heap_%x.bin' % (mbi.BaseAddress or 0)
        open(fn, 'wb').write(data)
        print('saved', fn, len(data), flush=True)
