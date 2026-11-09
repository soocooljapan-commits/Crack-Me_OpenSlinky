import ctypes, sys
from ctypes import wintypes

PATH = sys.argv[1] if len(sys.argv) > 1 else r'C:\Users\user\Pictures\crm\proxy\out\lib_beta_win.dll'
k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.GetProcAddress.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

dll = ctypes.CDLL(PATH)
base = ctypes.cast(dll._handle, ctypes.c_void_p).value
print('base', hex(base), flush=True)
addr = k32.GetProcAddress(ctypes.c_void_p(base), b'slinky_init')
print('slinky_init', hex(addr or 0), flush=True)
FN = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_wchar_p)
f = FN(addr)
for k in ('A' * 32, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345', 'wrong'):
    print(k, '->', f(k), flush=True)
