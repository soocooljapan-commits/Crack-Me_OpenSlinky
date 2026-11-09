import ctypes, sys

path = sys.argv[1] if len(sys.argv) > 1 else r'unpacked/lib_beta_win_unpacked.devirt.bin'
print('loading', path, flush=True)
try:
    dll = ctypes.CDLL(path)
except OSError as e:
    print('LOAD FAIL', e, flush=True)
    sys.exit(1)
print('loaded', flush=True)
if len(sys.argv) <= 2:
    sys.exit(0)
key = sys.argv[2]
fn = dll.slinky_init
fn.argtypes = [ctypes.c_wchar_p]
fn.restype = ctypes.c_int
print('calling', flush=True)
r = fn(key)
print('return', r, hex(r & 0xffffffff), flush=True)
