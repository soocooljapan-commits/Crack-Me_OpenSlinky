import ctypes, os, struct, sys
from ctypes import wintypes

PATH = r'C:\Users\user\Pictures\crm\packed.dll'
KEY = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345'

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.VirtualQuery.restype = ctypes.c_size_t
k32.VirtualQuery.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]


class MBI(ctypes.Structure):
    _fields_ = [('BaseAddress', ctypes.c_void_p), ('AllocationBase', ctypes.c_void_p),
                ('AllocationProtect', wintypes.DWORD), ('PartitionId', wintypes.WORD),
                ('RegionSize', ctypes.c_size_t), ('State', wintypes.DWORD),
                ('Protect', wintypes.DWORD), ('Type', wintypes.DWORD)]


dll = ctypes.CDLL(PATH)
base = ctypes.cast(dll._handle, ctypes.c_void_p).value
print('base', hex(base), flush=True)

FN = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_wchar_p)
print('ret', FN(base + 0x1000)(KEY), flush=True)

os.makedirs('regions', exist_ok=True)
addr = 0
idx = 0
while addr < 0x7fffffffffff:
    mbi = MBI()
    q = k32.VirtualQuery(ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
    if not q:
        break
    b = mbi.BaseAddress or 0
    size = mbi.RegionSize
    if mbi.State == 0x1000 and (mbi.Protect & 0x10 or mbi.Protect & 0x20 or mbi.Protect & 0x40 or mbi.Protect & 0x80) and size < 0x8000000:
        try:
            data = ctypes.string_at(b, size)
            fn = 'regions/r%03d_%x_%x_%x.bin' % (idx, b, size, mbi.Protect)
            open(fn, 'wb').write(data)
            print('%-60s %x %x prot=%x type=%x' % (fn, b, size, mbi.Protect, mbi.Type), flush=True)
            idx += 1
        except Exception as e:
            print('skip', hex(b), size, e, flush=True)
    addr = b + size
print('regions', idx, flush=True)
