import ctypes, struct, sys
from ctypes import wintypes

PATH = r'C:\Users\user\Pictures\crm\packed.dll'
KEY = b'A' * 32

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.VirtualAlloc.restype = ctypes.c_void_p
k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
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


hits = []
page_addr = None
base = None
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
        if len(hits) <= 200:
            print('GUARD#%d rip=%x off=%s addr=%x rax=%x rcx=%x rdx=%x rsi=%x rdi=%x r8=%x r9=%x r10=%x r11=%x' % (
                len(hits), ctx.Rip, hex(off) if off is not None else '?', addr,
                ctx.Rax, ctx.Rcx, ctx.Rdx, ctx.Rsi, ctx.Rdi, ctx.R8, ctx.R9, ctx.R10, ctx.R11), flush=True)
        if rearm:
            old = wintypes.DWORD()
            k32.VirtualProtect(ctypes.c_void_p(page_addr), 0x1000, 0x04, ctypes.byref(old))
            k32.VirtualProtect(ctypes.c_void_p(page_addr), 0x1000, 0x04 | 0x100, ctypes.byref(old))
        else:
            old = wintypes.DWORD()
            k32.VirtualProtect(ctypes.c_void_p(page_addr), 0x1000, 0x04, ctypes.byref(old))
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

page_addr = k32.VirtualAlloc(None, 0x1000, 0x3000, 0x04)
ctypes.memmove(page_addr, KEY, 32)
old = wintypes.DWORD()
k32.VirtualProtect(ctypes.c_void_p(page_addr), 0x1000, 0x04 | 0x100, ctypes.byref(old))

FN = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p)
print('calling 1290', flush=True)
r = FN(base + 0x1290)(page_addr)
print('RET', r, hex(r & 0xffffffff), 'hits', len(hits), flush=True)
