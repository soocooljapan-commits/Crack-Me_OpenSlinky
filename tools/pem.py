import re

d = open('unpacked/lib_beta_win_unpacked.devirt.bin', 'rb').read()

for m in re.finditer(rb'-----BEGIN [A-Z ]+-----', d):
    start = m.start()
    endm = re.search(rb'-----END [A-Z ]+-----', d[start:])
    if not endm:
        continue
    blob = d[start:start + endm.end()]
    print('===', hex(start), m.group().decode(), 'len', len(blob))
    print(blob.decode('latin1'))
    print()
