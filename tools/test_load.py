import ctypes, struct, sys
from ctypes import wintypes

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.VirtualProtect.restype = wintypes.BOOL
k32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
k32.VirtualQuery.restype = ctypes.c_size_t
k32.VirtualQuery.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]


class MBI(ctypes.Structure):
    _fields_ = [('BaseAddress', ctypes.c_void_p), ('AllocationBase', ctypes.c_void_p),
                ('AllocationProtect', wintypes.DWORD), ('PartitionId', wintypes.WORD),
                ('RegionSize', ctypes.c_size_t), ('State', wintypes.DWORD),
                ('Protect', wintypes.DWORD), ('Type', wintypes.DWORD)]


def prot(addr, new=None):
    old = wintypes.DWORD()
    if new is None:
        mbi = MBI()
        k32.VirtualQuery(ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
        return hex(mbi.Protect), hex(mbi.RegionSize), hex(mbi.BaseAddress or 0)
    r = k32.VirtualProtect(ctypes.c_void_p(addr), 0x1000, new, ctypes.byref(old))
    return r, ctypes.get_last_error(), hex(old.value)


path = sys.argv[1] if len(sys.argv) > 1 else r'C:\Users\user\Pictures\crm\devirt_patched.dll'


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


@ctypes.WINFUNCTYPE(wintypes.LONG, ctypes.POINTER(EXCEPTION_POINTERS))
def veh(info):
    rec = info.contents.ExceptionRecord.contents
    ctx = info.contents.ContextRecord.contents
    addr = rec.ExceptionInformation[1] if rec.NumberParameters >= 2 else 0
    print('EXC %x rip=%x off=%s addr=%x rax=%x rcx=%x rdx=%x rbx=%x rsi=%x rdi=%x' % (
        rec.ExceptionCode, ctx.Rip,
        hex(ctx.Rip - base) if base and ctx.Rip >= base else '?', addr or 0,
        ctx.Rax, ctx.Rcx, ctx.Rdx, ctx.Rbx, ctx.Rsi, ctx.Rdi), flush=True)
    return 0


k32.AddVectoredExceptionHandler(1, veh)

print('loading', path, flush=True)
try:
    dll = ctypes.CDLL(path)
except OSError as ex:
    print('LOAD FAIL', ex, flush=True)
    raise SystemExit(1)
base = ctypes.cast(dll._handle, ctypes.c_void_p).value
print('base', hex(base), flush=True)
print('text prot', prot(base + 0x1290), flush=True)
print('vp text', prot(base + 0x1290, 0x40), flush=True)
print('data prot', prot(base + 0x2e7000), flush=True)
print('vp data', prot(base + 0x2e7000, 0x04), flush=True)

FN = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_wchar_p)
for k in ('A' * 32, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345'):
    try:
        r = FN(base + 0x1000)(k)
        print('key', k, '->', r, hex(r & 0xffffffff), flush=True)
    except Exception as ex:
        print('call fail', ex, flush=True)
