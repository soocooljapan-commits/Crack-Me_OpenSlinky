import ctypes, sys, subprocess, json

PATH = r'C:\Users\user\Pictures\crm\packed.dll'
CHILD = r'''
import ctypes, sys
dll = ctypes.CDLL(sys.argv[1])
fn = dll.slinky_init
fn.argtypes = [ctypes.c_wchar_p]
fn.restype = ctypes.c_int
print(fn(sys.argv[2]), flush=True)
'''

if __name__ == '__main__':
    mode = sys.argv[1]
    keys = []
    if mode == 'chars':
        for c in range(0x20, 0x7f):
            keys.append(chr(c) * 32)
    elif mode == 'args':
        keys = sys.argv[2:]
    for k in keys:
        p = subprocess.run([sys.executable, '-c', CHILD, PATH, k], capture_output=True, text=True, timeout=60)
        out = p.stdout.strip().splitlines()
        print(repr(k), '->', out[-1] if out else 'CRASH', p.returncode)
