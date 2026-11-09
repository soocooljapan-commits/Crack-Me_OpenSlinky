import sys, traceback
try:
    import idb
    print('idb', idb.__file__)
    db = idb.from_file(r'unpacked/lib_beta_win_unpacked.devirt.bin.i64')
    print('opened', db)
    print('dir', [x for x in dir(db) if not x.startswith('_')][:60])
except Exception as e:
    traceback.print_exc()
