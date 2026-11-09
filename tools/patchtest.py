import ctypes
from ctypes import wintypes

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.VirtualProtect.restype = wintypes.BOOL
k32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
k32.VirtualQuery.restype = ctypes.c_size_t
k32.VirtualQuery.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]


class MBI(ctypes.Structure):
    _fields_ = [('BaseAddress', ctypes.c_void_p), ('AllocationBase', ctypes.c_void_p),
                ('AllocationProtect', wintypes.DWORD), ('PartitionId', wintypes.WORD),
                ('RegionSize', ctypes.c_size_t), ('State', wintypes.DWORD),
                ('Protect', wintypes.DWORD), ('Type', wintypes.DWORD)]


dll = ctypes.CDLL(r'C:\Users\user\Pictures\crm\packed.dll')
base = ctypes.cast(dll._handle, ctypes.c_void_p).value
site = base + 0x10c3
print('base', hex(base), 'site', hex(site))
mbi = MBI()
q = k32.VirtualQuery(ctypes.c_void_p(site), ctypes.byref(mbi), ctypes.sizeof(mbi))
print('vq', q, 'base', hex(mbi.BaseAddress or 0), 'size', hex(mbi.RegionSize), 'state', hex(mbi.State), 'prot', hex(mbi.Protect), 'type', hex(mbi.Type))
old = wintypes.DWORD()
r = k32.VirtualProtect(ctypes.c_void_p(site), 5, 0x40, ctypes.byref(old))
print('vp', r, 'err', ctypes.get_last_error(), 'old', hex(old.value))
try:
    ctypes.memmove(site, b'\x90' * 5, 5)
    print('write ok', ctypes.string_at(site, 5).hex())
except Exception as e:
    print('write fail', e)
