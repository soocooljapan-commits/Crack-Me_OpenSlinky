import ctypes, sys
from ctypes import wintypes

PATH = sys.argv[1] if len(sys.argv) > 1 else r'C:\Users\user\Pictures\crm\devirt_patched.dll'
k32 = ctypes.WinDLL('kernel32', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)
k32.GetCurrentProcess.restype = ctypes.c_void_p
psapi.EnumProcessModules.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
psapi.GetModuleBaseNameW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p, wintypes.DWORD]
psapi.GetModuleInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD]


class MODULEINFO(ctypes.Structure):
    _fields_ = [('lpBaseOfDll', ctypes.c_void_p), ('SizeOfImage', wintypes.DWORD), ('EntryPoint', ctypes.c_void_p)]


def snapshot():
    h = k32.GetCurrentProcess()
    arr = (ctypes.c_void_p * 1024)()
    needed = wintypes.DWORD()
    psapi.EnumProcessModules(h, arr, ctypes.sizeof(arr), ctypes.byref(needed))
    mods = []
    for i in range(needed.value // ctypes.sizeof(ctypes.c_void_p)):
        hm = arr[i]
        buf = ctypes.create_unicode_buffer(260)
        psapi.GetModuleBaseNameW(h, hm, buf, 260)
        mi = MODULEINFO()
        psapi.GetModuleInformation(h, hm, ctypes.byref(mi), ctypes.sizeof(mi))
        mods.append((buf.value, mi.lpBaseOfDll or 0, mi.SizeOfImage))
    return mods


def modof(addr):
    for name, b, sz in snapshot():
        if b <= addr < b + sz:
            return '%s+%x' % (name, addr - b)
    return '?'


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


@ctypes.WINFUNCTYPE(wintypes.LONG, ctypes.POINTER(EXCEPTION_POINTERS))
def veh(info):
    rec = info.contents.ExceptionRecord.contents
    ctx = info.contents.ContextRecord.contents
    addr = rec.ExceptionInformation[1] if rec.NumberParameters >= 2 else 0
    print('EXC %08x rip=%s addr=%x rax=%x rbx=%x rcx=%x rdx=%x' % (
        rec.ExceptionCode, modof(ctx.Rip), addr or 0, ctx.Rax, ctx.Rbx, ctx.Rcx, ctx.Rdx), flush=True)
    if ctx.Rsp:
        sp = ctypes.cast(ctypes.c_void_p(ctx.Rsp), ctypes.POINTER(ctypes.c_uint64))
        for i in range(12):
            v = sp[i]
            if v and v > 0x10000:
                print('   [rsp+%02x] %x  %s' % (i * 8, v, modof(v)), flush=True)
    return 0


k32.AddVectoredExceptionHandler(1, veh)
print('loading', PATH, flush=True)
dll = ctypes.CDLL(PATH)
print('base', hex(ctypes.cast(dll._handle, ctypes.c_void_p).value), flush=True)
