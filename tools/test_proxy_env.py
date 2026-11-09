import ctypes, os, sys, time
from ctypes import wintypes

PATH = sys.argv[1] if len(sys.argv) > 1 else r'C:\Users\user\Pictures\crm\proxy\out\lib_beta_win.dll'
os.environ['SLINKY_LICENSE'] = sys.argv[2] if len(sys.argv) > 2 else 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345'

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.GetProcAddress.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

t0 = time.time()
dll = ctypes.CDLL(PATH)
print('loaded in %.3fs' % (time.time() - t0), flush=True)
base = ctypes.cast(dll._handle, ctypes.c_void_p).value
FN = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_wchar_p)
f = FN(k32.GetProcAddress(ctypes.c_void_p(base), b'slinky_init'))
t0 = time.time()
r = f('ABCDEFGHIJKLMNOPQRSTUVWXYZ012345')
print('call ->', r, 'in %.3fs' % (time.time() - t0), flush=True)
time.sleep(1.5)
print('after-wait', flush=True)
