import ctypes, sys

path = sys.argv[1] if len(sys.argv) > 1 else r'unpacked/lib_beta_win_unpacked.devirt.bin'
key = sys.argv[2] if len(sys.argv) > 2 else 'A' * 32
try:
    dll = ctypes.CDLL(path)
except OSError as e:
    print('LOAD FAIL', e)
    sys.exit(1)
print('loaded')
try:
    fn = dll.slinky_init
except AttributeError:
    print('no export')
    sys.exit(1)
fn.argtypes = [ctypes.c_wchar_p]
fn.restype = ctypes.c_int
r = fn(key)
print('return', r, hex(r & 0xffffffff))
