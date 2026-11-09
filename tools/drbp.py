import ctypes, struct, sys
from ctypes import wintypes

PATH = r'C:\Users\user\Pictures\crm\packed.dll'
KEY = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345'

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
hits = []
phase = [0]
keybuf = [0]


def getctx():
    ctx = CONTEXT()
    ctx.ContextFlags = 0x00100010
    k32.GetThreadContext(k32.GetCurrentThread(), ctypes.byref(ctx))
    return ctx


def setctx(ctx):
    ctx.ContextFlags = 0x00100010
    k32.SetThreadContext(k32.GetCurrentThread(), ctypes.byref(ctx))


def dr7_for(slot, rw, ln):
    v = (1 << (2 * slot)) | (rw << (16 + 4 * slot)) | (ln << (18 + 4 * slot))
    return v


@ctypes.WINFUNCTYPE(wintypes.LONG, ctypes.POINTER(EXCEPTION_POINTERS))
def veh(info):
    rec = info.contents.ExceptionRecord.contents
    ctx = info.contents.ContextRecord.contents
    code = rec.ExceptionCode
    if code == 0x80000004:
        dr6 = ctx.Dr6
        if not (dr6 & 0xF):
            return 0
        off = (ctx.Rip - base) if base and ctx.Rip >= base else None
        if phase[0] == 0:
            print('EXEC BP at rip=%x off=%s rcx=%x rsi=%x rdi=%x' % (
                ctx.Rip, hex(off) if off is not None else '?', ctx.Rcx, ctx.Rsi, ctx.Rdi), flush=True)
            keybuf[0] = ctx.Rcx
            # set data breakpoints on buffer directly in exception context
            ctx.Dr0 = keybuf[0]
            ctx.Dr1 = keybuf[0] + 8
            ctx.Dr2 = keybuf[0] + 16
            ctx.Dr3 = keybuf[0] + 24
            ctx.Dr7 = 0
            for i in range(4):
                ctx.Dr7 |= dr7_for(i, 3, 2)
            ctx.Dr6 = 0
            phase[0] = 1
            return -1
        hits.append((ctx.Rip, dr6))
        if len(hits) <= 200:
            print('DATA#%d rip=%x off=%s dr6=%x rax=%x rcx=%x rdx=%x rsi=%x rdi=%x r8=%x' % (
                len(hits), ctx.Rip, hex(off) if off is not None else '?', dr6,
                ctx.Rax, ctx.Rcx, ctx.Rdx, ctx.Rsi, ctx.Rdi, ctx.R8), flush=True)
        ctx.Dr6 = 0
        return -1
    if code == 0xC0000005:
        addr = 0
        if rec.NumberParameters >= 2:
            addr = rec.ExceptionInformation[1] or 0
        off = (ctx.Rip - base) if base and ctx.Rip >= base else None
        print('AV rip=%x off=%s addr=%x' % (ctx.Rip, hex(off) if off is not None else '?', addr), flush=True)
        return 0
    return 0


k32.AddVectoredExceptionHandler(1, veh)

dll = ctypes.CDLL(PATH)
base = ctypes.cast(dll._handle, ctypes.c_void_p).value
print('base', hex(base), flush=True)

# set execute bp on 0x1290 entry
c = getctx()
c.Dr0 = base + 0x1290
c.Dr1 = c.Dr2 = c.Dr3 = 0
c.Dr7 = 0x1  # L0, rw=0 execute, len=0
c.Dr6 = 0
setctx(c)
print('dr7 set', flush=True)

FN = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_wchar_p)
r = FN(base + 0x1000)(KEY)
print('RET', r, 'hits', len(hits), 'keybuf', hex(keybuf[0]), flush=True)
if keybuf[0]:
    print('keybuf data', ctypes.string_at(keybuf[0], 32).hex(), flush=True)
