import struct, sys, os

SRC = sys.argv[1] if len(sys.argv) > 1 else 'packed.dll'
DST = sys.argv[2] if len(sys.argv) > 2 else 'lib_beta_win.dll'

d = bytearray(open(SRC, 'rb').read())
e = struct.unpack_from('<I', d, 0x3c)[0]
nsec = struct.unpack_from('<H', d, e + 6)[0]
optsz = struct.unpack_from('<H', d, e + 20)[0]
opt = e + 24
sec_align = struct.unpack_from('<I', d, opt + 32)[0]
file_align = struct.unpack_from('<I', d, opt + 36)[0]
size_img = struct.unpack_from('<I', d, opt + 56)[0]
size_hdr = struct.unpack_from('<I', d, opt + 60)[0]
sectab = opt + optsz

exp_rva, exp_sz = struct.unpack_from('<II', d, opt + 112)
print('export dir rva %x size %x' % (exp_rva, exp_sz))
print('sectab end %x, headers %x' % (sectab + nsec * 40, size_hdr))
assert sectab + (nsec + 1) * 40 <= size_hdr, 'no room for a new section header'

sections = []
for i in range(nsec):
    p = sectab + i * 40
    nm = bytes(d[p:p + 8]).rstrip(b'\x00').decode('latin1')
    vs, va, rs, ro = struct.unpack_from('<IIII', d, p + 8)
    sections.append((nm, va, vs, ro, rs))


def r2o(rva):
    for nm, va, vs, ro, rs in sections:
        if va <= rva < va + max(vs, rs):
            return ro + (rva - va)
    return None


# --- export table: find slinky_init and rewrite its function RVA ---
eo = r2o(exp_rva)
(chars, ts, maj, mnr, name_rva, ord_base, naddr, nnames, aor, anr, aord) = struct.unpack_from('<IIHHIIIIIII', d, eo)
print('exports: naddr %d nnames %d' % (naddr, nnames))
target = None
for i in range(nnames):
    nr = struct.unpack_from('<I', d, r2o(anr) + i * 4)[0]
    no = r2o(nr)
    nm = bytes(d[no:d.index(b'\x00', no)]).decode('latin1')
    ordv = struct.unpack_from('<H', d, r2o(aord) + i * 2)[0]
    fa = r2o(aor) + ordv * 4
    frva = struct.unpack_from('<I', d, fa)[0]
    print('  %-16s ord %d rva %x' % (nm, ordv, frva))
    if nm == 'slinky_init':
        target = fa

assert target is not None, 'slinky_init export not found'

# --- new section ---
new_rva = (size_img + sec_align - 1) & ~(sec_align - 1)
stub = bytes.fromhex('31c0c3')  # xor eax, eax ; ret
raw_size = (len(stub) + file_align - 1) & ~(file_align - 1)
raw_off = (len(d) + file_align - 1) & ~(file_align - 1)
d.extend(b'\x00' * (raw_off - len(d)))
d.extend(stub + b'\x00' * (raw_size - len(stub)))

# new section header
p = sectab + nsec * 40
d[p:p + 8] = b'.slkfix\x00'
struct.pack_into('<IIII', d, p + 8, raw_size, new_rva, raw_size, raw_off)
struct.pack_into('<I', d, p + 36, 0x60000020)  # CNT_CODE | MEM_EXECUTE | MEM_READ

struct.pack_into('<H', d, e + 6, nsec + 1)
struct.pack_into('<I', d, opt + 56, new_rva + ((raw_size + sec_align - 1) & ~(sec_align - 1)))

# export now points at the stub
struct.pack_into('<I', d, target, new_rva)

open(DST, 'wb').write(d)
print('wrote %s  new section rva %x raw %x  stub %s' % (DST, new_rva, raw_off, stub.hex()))
