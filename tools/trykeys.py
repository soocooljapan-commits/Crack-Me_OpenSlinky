import ctypes, sys, subprocess, hashlib

PATH = r'C:\Users\user\Pictures\crm\packed.dll'
CHILD = r'''
import ctypes, sys
dll = ctypes.CDLL(sys.argv[1])
fn = dll.slinky_init
fn.argtypes = [ctypes.c_wchar_p]
fn.restype = ctypes.c_int
print(fn(sys.argv[2]), flush=True)
'''

keys = [
    'e984c65498462e0bb9877136f4368535',
    'E984C65498462E0BB9877136F4368535',
    '353685f4367187b90b2e469854c684e9',
    'e984c65498462e0bb9877136f436853',
    'slinky' + 'e984c65498462e0bb9877136f4',
    'SLINKY' + 'E984C65498462E0BB9877136F4',
    'slinky-beta-' + 'e984c65498462e0bb987',
    'd965db1ec4d91a7aefd3171c5511097d',
    'd965db1ec4d91a7aefd3171c5511097dd500ccdf'[:32],
    '00000000000000000000000000000000',
    ' ' * 32,
]

blob = 'e984c65498462e0bb9877136f4368535'
words = ['slinky', 'Slinky', 'SLINKY', 'slinky beta', 'slinky-beta', 'slinkybeta',
         'libslinky', 'libslinky.dll', 'beta', 'slinky client', 'slinky.gg',
         'slinky.cc', 'slinky.io', 'slinky.dev', '2024', '2025', '2026',
         'slinky 2024', 'slinky 2025', 'slinky 2026', 'slinkyclient',
         'slinky cheat', 'slinky hack', 'slinky minecraft']
buildid = bytes.fromhex('d965db1ec4d91a7aefd3171c5511097dd500ccdf')
for w in words:
    for s in (w, w + 'slinky', 'slinky' + w, w + buildid.hex(), w + '2025'):
        if hashlib.md5(s.encode()).hexdigest() == blob:
            print('MD5 MATCH', repr(s))
print('md5 buildid', hashlib.md5(buildid).hexdigest())
print('md5 slinky+buildid', hashlib.md5(b'slinky' + buildid).hexdigest())
print('md5 buildid+slinky', hashlib.md5(buildid + b'slinky').hexdigest())

for k in keys:
    p = subprocess.run([sys.executable, '-c', CHILD, PATH, k], capture_output=True, text=True, timeout=60)
    out = p.stdout.strip().splitlines()
    print(repr(k), '->', out[-1] if out else 'CRASH', p.returncode)
