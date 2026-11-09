import ctypes, sys
from ctypes import wintypes

PATH = r'C:\Users\user\Pictures\crm\packed.dll'
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


base = [0]
hits = []


@ctypes.WINFUNCTYPE(wintypes.LONG, ctypes.POINTER(EXCEPTION_POINTERS))
def veh(info):
    rec = info.contents.ExceptionRecord.contents
    ctx = info.contents.ContextRecord.contents
    if rec.ExceptionCode == 0x80000001:
        hits.append(ctx.Rip)
        print('GUARD rip=%x off=%s addr=%x' % (ctx.Rip, hex(ctx.Rip - base[0]) if base[0] else '?',
                                               rec.ExceptionInformation[1] or 0), flush=True)
        old = wintypes.DWORD()
        k32.VirtualProtect(ctypes.c_void_p(rec.ExceptionInformation[1] & ~0xfff), 0x1000, 0x04, ctypes.byref(old))
        return -1
    return 0


k32.AddVectoredExceptionHandler(1, veh)

dll = ctypes.CDLL(PATH)
base[0] = ctypes.cast(dll._handle, ctypes.c_void_p).value
print('base', hex(base[0]), flush=True)

page = k32.VirtualAlloc(None, 0x1000, 0x3000, 0x04)
ctypes.memmove(page, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345'.encode('utf-16-le'), 64)
old = wintypes.DWORD()
k32.VirtualProtect(ctypes.c_void_p(page), 0x1000, 0x104, ctypes.byref(old))

FN = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p)
r = FN(base[0] + 0x1290)(page)
print('RET', r, hex(r & 0xffffffff), 'guard hits', len(hits), flush=True)
