import ctypes, os, struct, sys
from ctypes import wintypes

PATH = r'C:\Users\user\Pictures\crm\packed.dll'
KEY = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345'

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.GetCurrentThread.restype = ctypes.c_void_p
k32.SetThreadContext.restype = wintypes.BOOL
k32.SetThreadContext.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
k32.GetThreadContext.restype = wintypes.BOOL
k32.GetThreadContext.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
k32.GetModuleHandleExW.restype = wintypes.BOOL
k32.GetModuleHandleExW.argtypes = [wintypes.DWORD, wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
k32.GetModuleFileNameW.restype = wintypes.DWORD
k32.GetModuleFileNameW.argtypes = [ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
k32.VirtualQuery.restype = ctypes.c_size_t
k32.VirtualQuery.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]


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


class MBI(ctypes.Structure):
    _fields_ = [('BaseAddress', ctypes.c_void_p), ('AllocationBase', ctypes.c_void_p),
                ('AllocationProtect', wintypes.DWORD), ('PartitionId', wintypes.WORD),
                ('RegionSize', ctypes.c_size_t), ('State', wintypes.DWORD),
                ('Protect', wintypes.DWORD), ('Type', wintypes.DWORD)]


base = None
hits = []
phase = [0]
keybuf = [0]


def dr7_for(slot, rw, ln):
    return (1 << (2 * slot)) | (rw << (16 + 4 * slot)) | (ln << (18 + 4 * slot))


@ctypes.WINFUNCTYPE(wintypes.LONG, ctypes.POINTER(EXCEPTION_POINTERS))
def veh(info):
    rec = info.contents.ExceptionRecord.contents
    ctx = info.contents.ContextRecord.contents
    code = rec.ExceptionCode
    if code == 0x80000004:
        dr6 = ctx.Dr6
        if not (dr6 & 0xF):
            return 0
        if phase[0] == 0:
            keybuf[0] = ctx.Rcx
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
        hits.append((ctx.Rip, dr6 & 0xF, ctx.Rax, ctx.Rcx, ctx.Rdx, ctx.Rsi, ctx.Rdi))
        ctx.Dr6 = 0
        return -1
    return 0


k32.AddVectoredExceptionHandler(1, veh)

dll = ctypes.CDLL(PATH)
base = ctypes.cast(dll._handle, ctypes.c_void_p).value
print('base', hex(base), flush=True)

c = CONTEXT()
c.ContextFlags = 0x00100010
k32.GetThreadContext(k32.GetCurrentThread(), ctypes.byref(c))
c.Dr0 = base + 0x1290
c.Dr7 = 0x1
c.Dr6 = 0
k32.SetThreadContext(k32.GetCurrentThread(), ctypes.byref(c))

FN = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_wchar_p)
r = FN(base + 0x1000)(KEY)
print('RET', r, 'hits', len(hits), 'keybuf', hex(keybuf[0]), flush=True)

# clear DR
c = CONTEXT()
c.ContextFlags = 0x00100010
k32.GetThreadContext(k32.GetCurrentThread(), ctypes.byref(c))
c.Dr0 = c.Dr1 = c.Dr2 = c.Dr3 = 0
c.Dr7 = 0
c.Dr6 = 0
k32.SetThreadContext(k32.GetCurrentThread(), ctypes.byref(c))

seen = {}
for h in hits:
    rip = h[0]
    if rip in seen:
        seen[rip][1].append(h[1])
    else:
        seen[rip] = [h, [h[1]]]

print('unique rips', len(seen), flush=True)
for rip, (h, slots) in seen.items():
    mod = ctypes.c_void_p()
    ok = k32.GetModuleHandleExW(0x4, wintypes.LPCWSTR(rip), ctypes.byref(mod))
    name = '?'
    if ok:
        buf = ctypes.create_unicode_buffer(512)
        k32.GetModuleFileNameW(mod, buf, 512)
        name = buf.value
        rva = rip - mod.value
    else:
        rva = 0
    mbi = MBI()
    k32.VirtualQuery(ctypes.c_void_p(rip), ctypes.byref(mbi), ctypes.sizeof(mbi))
    print('%x rva=%x mod=%s slots=%s regs=%s vqbase=%x size=%x prot=%x type=%x' % (
        rip, rva, os.path.basename(name), slots[:20], [hex(x) for x in h[2:]], mbi.BaseAddress or 0, mbi.RegionSize, mbi.Protect, mbi.Type), flush=True)
