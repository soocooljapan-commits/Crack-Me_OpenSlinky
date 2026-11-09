import re

d = open('solution/module_dump.bin', 'rb').read()
start, end = 0x140000, 0x140600
blob = d[start:end]
for m in re.finditer(rb'[ -~]{2,200}', blob):
    print('%08x %r' % (start + m.start(), m.group().decode('latin1')))
