import ctypes, struct, sys
from ctypes import wintypes

PATH = r'C:\Users\user\Pictures\crm\packed.dll'
KEY = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345'

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.GetCurrentThread.restype = ctypes.c_void_p
k32.GetCurrentThread.restype = ctypes.c_void_p
k32.SetThreadContext.restype = wintypes.BOOL
k32.SetThreadContext.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
k32.GetThreadContext.restype = wintypes.BOOL
k32.GetThreadContext.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
k32.VirtualProtect.restype = wintypes.BOOL
k32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]


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
        hits.append((ctx.Rip, dr6))
        if len(hits) <= 300:
            print('DBG#%d rip=%x off=%s dr6=%x rax=%x rcx=%x rdx=%x rsi=%x rdi=%x' % (
                len(hits), ctx.Rip, hex(off) if off is not None else '?', dr6,
                ctx.Rax, ctx.Rcx, ctx.Rdx, ctx.Rsi, ctx.Rdi), flush=True)
        # clear dr6
        ctx.Dr6 = 0
        return -1
    if code == 0xC0000005:
        addr = 0
        if rec.NumberParameters >= 2:
            addr = rec.ExceptionInformation[1] or 0
        off = (ctx.Rip - base) if base and ctx.Rip >= base else None
        print('AV rip=%x off=%s addr=%x' % (ctx.Rip, hex(off) if off is not None else '?', addr), flush=True)
        hits.append(('av', ctx.Rip))
        if len(hits) > 50:
            raise SystemExit(9)
        return -1
    return 0


k32.AddVectoredExceptionHandler(1, veh)

dll = ctypes.CDLL(PATH)
base = ctypes.cast(dll._handle, ctypes.c_void_p).value
print('base', hex(base), flush=True)

real = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p)(base + 0x1290)

seen_bufs = []


def set_dr(addr):
    th = k32.GetCurrentThread()
    ctx = CONTEXT()
    ctx.ContextFlags = 0x00100010
    if not k32.GetThreadContext(th, ctypes.byref(ctx)):
        print('GetThreadContext fail', ctypes.get_last_error(), flush=True)
        return
    ctx.Dr0 = addr
    ctx.Dr1 = addr + 8
    ctx.Dr2 = addr + 16
    ctx.Dr3 = addr + 24
    dr7 = 0
    for i in range(4):
        dr7 |= (1 << (2 * i)) | (3 << (16 + 4 * i)) | (2 << (18 + 4 * i))
    ctx.Dr7 = dr7
    ctx.Dr6 = 0
    if not k32.SetThreadContext(th, ctypes.byref(ctx)):
        print('SetThreadContext fail', ctypes.get_last_error(), flush=True)


def clear_dr():
    th = k32.GetCurrentThread()
    ctx = CONTEXT()
    ctx.ContextFlags = 0x00100010
    k32.GetThreadContext(th, ctypes.byref(ctx))
    ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0
    ctx.Dr7 = 0
    ctx.Dr6 = 0
    k32.SetThreadContext(th, ctypes.byref(ctx))


@ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p)
def hook(buf):
    if len(seen_bufs) < 8:
        seen_bufs.append(buf)
        print('HOOK buf=%x data=%s' % (buf, ctypes.string_at(buf, 32).hex()), flush=True)
    set_dr(buf)
    r = real(buf)
    clear_dr()
    print('real ret', r, 'hits', len(hits), flush=True)
    return r


# patch call at base+0x10c3 (5 bytes) to call a nearby trampoline
site = base + 0x10c3
old = ctypes.string_at(site, 5)
k32.VirtualAlloc.restype = ctypes.c_void_p
k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
tramp = None
for delta in range(0x3540000, 0x80000000, 0x100000):
    t = k32.VirtualAlloc(ctypes.c_void_p(base + delta), 0x1000, 0x3000, 0x40)
    if t:
        tramp = t
        break
print('tramp', hex(tramp or 0), flush=True)
if not tramp:
    raise SystemExit('no trampoline')
hookaddr = ctypes.cast(hook, ctypes.c_void_p).value
stub = b'\x48\xb8' + struct.pack('<Q', hookaddr) + b'\xff\xe0'
ctypes.memmove(tramp, stub, len(stub))
rel = tramp - (site + 5)
print('old call', old.hex(), 'hook', hex(hookaddr), 'rel', hex(rel & 0xffffffff), flush=True)
patch = b'\xe8' + struct.pack('<i', rel)
oldprot = wintypes.DWORD()
k32.VirtualProtect(ctypes.c_void_p(site), 5, 0x40, ctypes.byref(oldprot))
ctypes.memmove(site, patch, 5)
k32.VirtualProtect(ctypes.c_void_p(site), 5, oldprot.value, ctypes.byref(oldprot))

FN = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_wchar_p)
print('calling slinky_init', flush=True)
r = FN(base + 0x1000)(KEY)
print('RET', r, 'hits', len(hits), flush=True)
