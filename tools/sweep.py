import ctypes, sys

path = sys.argv[1]
dll = ctypes.CDLL(path)
fn = dll.slinky_init
fn.argtypes = [ctypes.c_wchar_p]
fn.restype = ctypes.c_int

for c in range(0x20, 0x7f):
    k = chr(c) * 32
    r = fn(k)
    if r != 1000:
        print('char', repr(chr(c)), 'ret', r, hex(r & 0xffffffff))
for n in (0, 1, 8, 16, 24, 31, 32, 33, 40, 64):
    k = 'B' * n
    print('len', n, 'ret', fn(k))
