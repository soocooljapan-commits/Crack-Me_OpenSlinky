import struct
from capstone import *
from pe import d, secs, r2o, o2r, parse_imports

imps = parse_imports()
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
md.skipdata = True


def readstr(rva):
    o = r2o(rva)
    if o is None:
        return None
    end = d.index(b'\x00', o)
    s = d[o:end]
    if not s:
        return None
    try:
        t = s.decode('latin1')
    except Exception:
        return None
    return t if all(32 <= ord(c) < 127 for c in t) else None


def scan(name, va, vs, ro, rs):
    code = d[ro:ro + rs]
    for ins in md.disasm(code, va):
        if ins.mnemonic == 'call' and 'rip' in ins.op_str:
            try:
                disp = int(ins.op_str.split('rip + ')[1].split(']')[0], 16)
            except Exception:
                continue
            tgt = ins.address + ins.size + disp
            nm = imps.get(tgt)
            if nm:
                print('%s %08x call %-40s %s' % (name, ins.address, nm, ins.op_str))
        elif ins.mnemonic in ('lea', 'mov') and 'rip' in ins.op_str:
            try:
                disp = int(ins.op_str.split('rip + ')[1].split(']')[0], 16)
            except Exception:
                continue
            tgt = ins.address + ins.size + disp
            s = readstr(tgt)
            if s and len(s) >= 4:
                print('%s %08x %s %-30s ; "%s"' % (name, ins.address, ins.mnemonic, ins.op_str, s[:90]))


if __name__ == '__main__':
    import sys
    which = sys.argv[1] if len(sys.argv) > 1 else '.text'
    for name, va, vs, ro, rs in secs:
        if name == which:
            scan(name, va, vs, ro, rs)
