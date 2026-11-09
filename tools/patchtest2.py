import ctypes
from ctypes import wintypes

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
ntdll = ctypes.WinDLL('ntdll')

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

# check hooks on VirtualProtect
vp = ctypes.cast(k32.VirtualProtect, ctypes.c_void_p).value
print('VirtualProtect at', hex(vp), 'bytes', ctypes.string_at(vp, 16).hex())
ntp = ctypes.cast(ntdll.NtProtectVirtualMemory, ctypes.c_void_p).value
print('NtProtectVirtualMemory at', hex(ntp), 'bytes', ctypes.string_at(ntp, 16).hex())

NtProtectVirtualMemory = ntdll.NtProtectVirtualMemory
NtProtectVirtualMemory.restype = ctypes.c_long
NtProtectVirtualMemory.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_size_t), wintypes.ULONG, ctypes.POINTER(wintypes.ULONG)]

addr = ctypes.c_void_p(site)
size = ctypes.c_size_t(5)
oldp = wintypes.ULONG()
st = NtProtectVirtualMemory(ctypes.c_void_p(-1), ctypes.byref(addr), ctypes.byref(size), 0x40, ctypes.byref(oldp))
print('ntp status', hex(st & 0xffffffff), 'old', hex(oldp.value), 'addr', hex(addr.value), 'size', size.value)
if st == 0:
    try:
        ctypes.memmove(site, b'\x90' * 5, 5)
        print('write ok', ctypes.string_at(site, 5).hex())
    except Exception as e:
        print('write fail', e)
    # restore
    addr = ctypes.c_void_p(site)
    size = ctypes.c_size_t(5)
    st = NtProtectVirtualMemory(ctypes.c_void_p(-1), ctypes.byref(addr), ctypes.byref(size), oldp.value, ctypes.byref(oldp))
    print('restore', hex(st & 0xffffffff))
