import ctypes, sys
from ctypes import wintypes

PATH = r'C:\Users\user\Pictures\crm\packed.dll'
KEY = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345'
MAXSTEPS = int(sys.argv[1]) if len(sys.argv) > 1 else 20000

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.GetCurrentThread.restype = ctypes.c_void_p
k32.SetThreadContext.restype = wintypes.BOOL
k32.SetThreadContext.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
k32.GetThreadContext.restype = wintypes.BOOL
k32.GetThreadContext.argtypes = [ctypes.c_void_p, ctypes.c_void_p]


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
steps = []
started = [False]
done = [False]
prev = [0]


@ctypes.WINFUNCTYPE(wintypes.LONG, ctypes.POINTER(EXCEPTION_POINTERS))
def veh(info):
    rec = info.contents.ExceptionRecord.contents
    ctx = info.contents.ContextRecord.contents
    code = rec.ExceptionCode
    if code == 0x80000004:
        dr6 = ctx.Dr6
        if not started[0]:
            if not (dr6 & 0xF):
                return 0
            started[0] = True
            ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0
            ctx.Dr7 = 0
            ctx.Dr6 = 0
            ctx.EFlags |= 0x100
            return -1
        rip = ctx.Rip
        steps.append(rip)
        if len(steps) >= MAXSTEPS:
            done[0] = True
            ctx.EFlags &= ~0x100
            return 0
        ctx.EFlags |= 0x100
        return -1
    if code == 0xC0000005:
        addr = rec.ExceptionInformation[1] if rec.NumberParameters >= 2 else 0
        print('AV rip=%x off=%s addr=%x' % (ctx.Rip, hex(ctx.Rip - base) if base and ctx.Rip >= base else '?', addr or 0), flush=True)
        done[0] = True
        ctx.EFlags &= ~0x100
        return 0
    return 0


k32.AddVectoredExceptionHandler(1, veh)

dll = ctypes.CDLL(PATH)
base = ctypes.cast(dll._handle, ctypes.c_void_p).value
print('base', hex(base), flush=True)

c = CONTEXT()
c.ContextFlags = 0x00100010
k32.GetThreadContext(k32.GetCurrentThread(), ctypes.byref(c))
c.Dr0 = base + 0x1290
c.Dr1 = c.Dr2 = c.Dr3 = 0
c.Dr7 = 0x1
c.Dr6 = 0
k32.SetThreadContext(k32.GetCurrentThread(), ctypes.byref(c))

FN = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_wchar_p)
print('call', flush=True)
r = FN(base + 0x1000)(KEY)
print('RET', r, hex(r & 0xffffffff), 'steps', len(steps), 'done', done[0], flush=True)

# print transitions
last = None
runs = []
for i, rip in enumerate(steps):
    if last is not None and rip == last + 0 and False:
        pass
    if last is None or rip != last:
        runs.append([rip, 1])
    else:
        runs[-1][1] += 1
    last = rip
print('unique-ish runs', len(runs), flush=True)
for i, (rip, n) in enumerate(runs[:400]):
    off = (rip - base) if base and rip >= base else None
    print('%5d x%-4d rip=%x off=%s' % (i, n, rip, hex(off) if off is not None else '?'), flush=True)
