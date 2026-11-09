import ctypes, sys, struct
from ctypes import wintypes

PATH = sys.argv[1] if len(sys.argv) > 1 else r'C:\Users\user\Pictures\crm\devirt_unpatched.dll'
MODE = sys.argv[2] if len(sys.argv) > 2 else '1000'
KEY = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345'

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


base = None
page = None
hits = []


@ctypes.WINFUNCTYPE(wintypes.LONG, ctypes.POINTER(EXCEPTION_POINTERS))
def veh(info):
    rec = info.contents.ExceptionRecord.contents
    ctx = info.contents.ContextRecord.contents
    code = rec.ExceptionCode
    if code == 0x80000001:
        addr = rec.ExceptionInformation[1] or 0
        off = (ctx.Rip - base) if base and ctx.Rip >= base else None
        hits.append((ctx.Rip, addr))
        if len(hits) <= 300:
            print('GUARD#%d rip=%x off=%s addr=%x rax=%x rcx=%x rdx=%x rsi=%x rdi=%x r8=%x r9=%x' % (
                len(hits), ctx.Rip, hex(off) if off is not None else '?', addr,
                ctx.Rax, ctx.Rcx, ctx.Rdx, ctx.Rsi, ctx.Rdi, ctx.R8, ctx.R9), flush=True)
        old = wintypes.DWORD()
        k32.VirtualProtect(ctypes.c_void_p(page), 0x1000, 0x04, ctypes.byref(old))
        return -1
    return 0


k32.AddVectoredExceptionHandler(1, veh)

dll = ctypes.CDLL(PATH)
base = ctypes.cast(dll._handle, ctypes.c_void_p).value
print('base', hex(base), 'mode', MODE, flush=True)

page = k32.VirtualAlloc(None, 0x1000, 0x3000, 0x04)
print('page', hex(page), flush=True)

if MODE == '1000':
    ctypes.memmove(page, KEY.encode('utf-16-le'), 64)
    old = wintypes.DWORD()
    k32.VirtualProtect(ctypes.c_void_p(page), 0x1000, 0x04 | 0x100, ctypes.byref(old))
    FN = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p)
    r = FN(base + 0x1000)(page)
    print('RET', r, hex(r & 0xffffffff), 'hits', len(hits), flush=True)
else:
    ctypes.memmove(page, KEY.encode(), 32)
    old = wintypes.DWORD()
    k32.VirtualProtect(ctypes.c_void_p(page), 0x1000, 0x04 | 0x100, ctypes.byref(old))
    FN = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p)
    r = FN(base + 0x1290)(page)
    print('RET', r, hex(r & 0xffffffff), 'hits', len(hits), flush=True)
