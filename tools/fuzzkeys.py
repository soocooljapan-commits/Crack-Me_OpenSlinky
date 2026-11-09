import ctypes, sys, subprocess, random, string

PATH = r'C:\Users\user\Pictures\crm\packed.dll'
CHILD = r'''
import ctypes, sys
dll = ctypes.CDLL(sys.argv[1])
fn = dll.slinky_init
fn.argtypes = [ctypes.c_wchar_p]
fn.restype = ctypes.c_int
print(fn(sys.argv[2]), flush=True)
'''

keys = []
random.seed(1)
for i in range(200):
    keys.append(''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32)))
for k in keys:
    p = subprocess.run([sys.executable, '-c', CHILD, PATH, k], capture_output=True, text=True, timeout=60)
    out = p.stdout.strip().splitlines()
    print(k, out[-1] if out else 'CRASH')
