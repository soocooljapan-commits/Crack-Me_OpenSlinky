import ctypes, sys, time

path = sys.argv[1]
dll = ctypes.CDLL(path)
fn = dll.slinky_init
fn.argtypes = [ctypes.c_wchar_p]
fn.restype = ctypes.c_int

keys = sys.argv[2:] or ['A' * 32]
for k in keys:
    t = time.time()
    r = fn(k)
    print(repr(k), '->', r, hex(r & 0xffffffff), 'in %.2fs' % (time.time() - t), flush=True)
