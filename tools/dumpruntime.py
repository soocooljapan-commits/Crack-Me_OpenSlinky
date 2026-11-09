import ctypes, sys
from ctypes import wintypes

PATH = sys.argv[1] if len(sys.argv) > 1 else r'C:\Users\user\Pictures\crm\packed.dll'
OUT = sys.argv[2] if len(sys.argv) > 2 else 'text_runtime.bin'

k32 = ctypes.WinDLL('kernel32')
dll = ctypes.CDLL(PATH)
base = ctypes.cast(dll._handle, ctypes.c_void_p).value
print('base', hex(base), flush=True)

# dump whole image mapping size from headers
import struct
data = open(PATH, 'rb').read()
e = struct.unpack_from('<I', data, 0x3c)[0]
optsz = struct.unpack_from('<H', data, e + 20)[0]
opt = e + 24
sizeimg = struct.unpack_from('<I', data, opt + 56)[0]
print('sizeimg', hex(sizeimg), flush=True)
buf = ctypes.string_at(base, sizeimg)
open(OUT, 'wb').write(buf)
print('wrote', OUT, len(buf), flush=True)

nsec = struct.unpack_from('<H', data, e + 6)[0]
secoff = opt + optsz
for i in range(nsec):
    o = secoff + i * 40
    name = data[o:o + 8].rstrip(b'\x00').decode('latin1')
    vs, va, rs, ro = struct.unpack_from('<IIII', data, o + 8)
    print('%-9s rva %08x vs %x' % (name, va, vs))
