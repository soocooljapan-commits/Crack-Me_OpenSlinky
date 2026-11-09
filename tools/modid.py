import ctypes
from ctypes import wintypes

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.GetModuleHandleExW.restype = wintypes.BOOL
k32.GetModuleHandleExW.argtypes = [wintypes.DWORD, wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
k32.GetModuleFileNameW.restype = wintypes.DWORD
k32.GetModuleFileNameW.argtypes = [ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
k32.VirtualQuery.restype = ctypes.c_size_t
k32.VirtualQuery.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]


class MBI(ctypes.Structure):
    _fields_ = [('BaseAddress', ctypes.c_void_p), ('AllocationBase', ctypes.c_void_p),
                ('AllocationProtect', wintypes.DWORD), ('PartitionId', wintypes.WORD),
                ('RegionSize', ctypes.c_size_t), ('State', wintypes.DWORD),
                ('Protect', wintypes.DWORD), ('Type', wintypes.DWORD)]


dll = ctypes.CDLL(r'C:\Users\user\Pictures\crm\packed.dll')
base = ctypes.cast(dll._handle, ctypes.c_void_p).value
print('base', hex(base))

for addr in (0x7fff603a1007, 0x7fff60321000, base, base + 0x325000, base + 0x35c1007):
    h = ctypes.c_void_p()
    ok = k32.GetModuleHandleExW(0x4, wintypes.LPCWSTR(addr), ctypes.byref(h))
    buf = ctypes.create_unicode_buffer(512)
    if ok:
        k32.GetModuleFileNameW(h, buf, 512)
        print(hex(addr), '->', hex(h.value or 0), buf.value)
    else:
        print(hex(addr), '-> no module', ctypes.get_last_error())
    mbi = MBI()
    k32.VirtualQuery(ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
    print('   vq base', hex(mbi.BaseAddress or 0), 'size', hex(mbi.RegionSize), 'prot', hex(mbi.Protect), 'type', hex(mbi.Type), 'allocbase', hex(mbi.AllocationBase or 0))
