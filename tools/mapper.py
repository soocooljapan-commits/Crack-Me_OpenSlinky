import ctypes, struct, sys
from ctypes import wintypes

PATH = sys.argv[1] if len(sys.argv) > 1 else r'unpacked/lib_beta_win_unpacked.devirt.bin'
KEY = sys.argv[2] if len(sys.argv) > 2 else 'A' * 32
MODE = sys.argv[3] if len(sys.argv) > 3 else 'init'

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.VirtualAlloc.restype = ctypes.c_void_p
k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
k32.LoadLibraryW.restype = ctypes.c_void_p
k32.LoadLibraryW.argtypes = [wintypes.LPCWSTR]
k32.GetProcAddress.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

data = open(PATH, 'rb').read()
e = struct.unpack_from('<I', data, 0x3c)[0]
nsec = struct.unpack_from('<H', data, e + 6)[0]
optsz = struct.unpack_from('<H', data, e + 20)[0]
opt = e + 24
secoff = opt + optsz
sizehdr = struct.unpack_from('<I', data, opt + 60)[0]
sizeimg = struct.unpack_from('<I', data, opt + 56)[0]
imgbase = struct.unpack_from('<Q', data, opt + 24)[0]
secs = []
for i in range(nsec):
    o = secoff + i * 40
    name = data[o:o + 8].rstrip(b'\x00').decode('latin1')
    vs, va, rs, ro = struct.unpack_from('<IIII', data, o + 8)
    secs.append((name, va, vs, ro, rs))

MEM_COMMIT_RESERVE = 0x3000
PAGE_EXECUTE_READWRITE = 0x40
mem = k32.VirtualAlloc(ctypes.c_void_p(imgbase), sizeimg, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
print('alloc at', hex(mem or 0), 'want', hex(imgbase), flush=True)
if not mem:
    sys.exit(1)
if mem != imgbase:
    print('WARN loaded at different base, no relocs', flush=True)

ctypes.memmove(mem, data[:sizehdr], sizehdr)
for name, va, vs, ro, rs in secs:
    if rs:
        ctypes.memmove(mem + va, data[ro:ro + rs], rs)


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
resolved = 0
failed = []
while True:
    ilt, ts, fc, nrva, iat = struct.unpack_from('<IIIII', data, o + i * 20)
    if ilt == 0 and nrva == 0 and fc == 0:
        break
    dllname = cstr(nrva)
    h = k32.LoadLibraryW(dllname)
    if not h:
        failed.append(dllname)
        print('FAIL DLL', dllname, flush=True)
    t = ilt or iat
    j = 0
    while True:
        v = struct.unpack_from('<Q', data, r2o(t) + 8 * j)[0]
        if v == 0:
            break
        if v >> 63:
            nm = ctypes.cast(v & 0xffff, ctypes.c_void_p)
            addr = k32.GetProcAddress(h, ctypes.cast(v & 0xffff, ctypes.c_char_p)) if False else None
            addr = None
        else:
            nmstr = cstr((v & 0x7fffffff) + 2)
            addr = k32.GetProcAddress(h, nmstr.encode())
            if not addr:
                failed.append(dllname + '!' + nmstr)
        if addr:
            ctypes.c_uint64.from_address(mem + iat + 8 * j).value = addr
            resolved += 1
        j += 1
    i += 1

print('resolved', resolved, 'failed', len(failed), flush=True)
if failed:
    print(failed[:20], flush=True)

keybuf = ctypes.create_unicode_buffer(KEY)
if MODE == 'init':
    fnaddr = mem + 0x1000
elif MODE == 'check':
    fnaddr = mem + 0x10f0
else:
    fnaddr = mem + int(MODE, 16)
FN = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_wchar_p)
fn = FN(fnaddr)
print('calling', hex(fnaddr), flush=True)
r = fn(keybuf)
print('RET', r, hex(r & 0xffffffff), flush=True)
