import ctypes, struct, sys
from ctypes import wintypes

PATH = r'C:\Users\user\Pictures\crm\packed.dll'
KEY = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345'
RAW = KEY.encode()

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
r = FN(base + 0x1000)(KEY)
print('first ret', r, flush=True)
# second call returns 0 due to guard
r2 = FN(base + 0x1000)(KEY)
print('second ret', r2, flush=True)

addr = 0
found = []
while addr < 0x7fffffffffff:
    mbi = MBI()
    q = k32.VirtualQuery(ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
    if not q:
        break
    b = mbi.BaseAddress or 0
    size = mbi.RegionSize
    if mbi.State == 0x1000 and (mbi.Protect & 0xff) in (0x02, 0x04, 0x20, 0x40, 0x80) and size < 0x40000000:
        try:
            data = ctypes.string_at(b, size)
            i = 0
            while True:
                i = data.find(RAW, i)
                if i < 0:
                    break
                found.append(b + i)
                i += 1
        except Exception:
            pass
    addr = b + size

print('found', len(found), [hex(x) for x in found[:20]], flush=True)
for x in found[:20]:
    print('ctx', hex(x), ctypes.string_at(x - 32, 96).hex(), flush=True)
