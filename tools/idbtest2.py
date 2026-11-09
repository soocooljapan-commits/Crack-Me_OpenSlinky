import idb

path = r'unpacked/lib_beta_win_unpacked.devirt.bin.i64'
with idb.from_file(path) as db:
    print('opened', type(db))
    print('attrs', [a for a in dir(db) if not a.startswith('_')])
    try:
        print('names type', type(db.names))
        n = list(db.names.items())
        print('names count', len(n))
        for ea, name in n[:30]:
            print(hex(ea), name)
    except Exception as e:
        print('names fail', type(e).__name__, e)
    try:
        fns = list(db.functions.items())
        print('funcs count', len(fns))
        for ea, f in fns[:10]:
            print(hex(ea), f)
    except Exception as e:
        print('funcs fail', type(e).__name__, e)
    try:
        ents = list(db.entries.items())
        print('entries', len(ents))
        for ea, e in ents[:10]:
            print(hex(ea), e)
    except Exception as e:
        print('entries fail', type(e).__name__, e)
