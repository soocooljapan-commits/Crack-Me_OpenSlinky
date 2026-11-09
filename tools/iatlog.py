import ctypes, struct, sys, time
from ctypes import wintypes

PATH = sys.argv[1]
KEY = sys.argv[2] if len(sys.argv) > 2 else 'A' * 32

# parse PE import table from file
data = open(PATH, 'rb').read()
e = struct.unpack_from('<I', data, 0x3c)[0]
nsec = struct.unpack_from('<H', data, e + 6)[0]
optsz = struct.unpack_from('<H', data, e + 20)[0]
opt = e + 24
secoff = opt + optsz
secs = []
for i in range(nsec):
    o = secoff + i * 40
    name = data[o:o + 8].rstrip(b'\x00').decode('latin1')
    vs, va, rs, ro = struct.unpack_from('<IIII', data, o + 8)
    secs.append((name, va, vs, ro, rs))


def r2o(rva):
    for n, va, vs, ro, rs in secs:
        if va <= rva < va + max(vs, rs):
            return ro + (rva - va)
    return None


def cstr(rva):
    o = r2o(rva)
    end = data.index(b'\x00', o)
    return data[o:end].decode('latin1', 'replace')


imp_rva, imp_sz = struct.unpack_from('<II', data, opt + 120)
o = r2o(imp_rva)
i = 0
imports = []
while True:
    ilt, ts, fc, nrva, iat = struct.unpack_from('<IIIII', data, o + i * 20)
    if ilt == 0 and nrva == 0 and fc == 0:
        break
    dll = cstr(nrva)
    t = ilt or iat
    j = 0
    while True:
        v = struct.unpack_from('<Q', data, r2o(t) + 8 * j)[0]
        if v == 0:
            break
        nm = 'ord%d' % (v & 0xffff) if v >> 63 else cstr((v & 0x7fffffff) + 2)
        imports.append((dll, nm, iat + 8 * j))
        j += 1
    i += 1

dll = ctypes.CDLL(PATH)
base = ctypes.cast(dll._handle, ctypes.c_void_p).value
print('base', hex(base), 'imports', len(imports), flush=True)

LOG = []

GENERIC = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64,
                           ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64,
                           ctypes.c_uint64)

keep = []


def make_cb(dllname, name, orig):
    def cb(a0, a1, a2, a3, a4, a5):
        LOG.append((dllname, name, a0, a1, a2, a3))
        if len(LOG) < 400:
            print('CALL %s!%s (%x,%x,%x,%x)' % (dllname, name, a0, a1, a2, a3), flush=True)
        try:
            fn = GENERIC(orig)
            r = fn(a0, a1, a2, a3, a4, a5)
        except Exception as ex:
            r = 0
        return r
    c = GENERIC(cb)
    keep.append(c)
    return c


# hook everything except a few that must not be called
skip = set()
for dllname, name, iat in imports:
    slot = base + iat
    orig = ctypes.c_uint64.from_address(slot).value
    if not orig:
        continue
    cb = make_cb(dllname, name, orig)
    ctypes.c_uint64.from_address(slot).value = ctypes.cast(cb, ctypes.c_void_p).value

fn = dll.slinky_init
fn.argtypes = [ctypes.c_wchar_p]
fn.restype = ctypes.c_int
print('call', flush=True)
r = fn(KEY)
print('RET', r, flush=True)
