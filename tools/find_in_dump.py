import re

d = open('solution/module_dump.bin', 'rb').read()

needles = [b'Invalid license key', b'Authentication failed: %s', b'API error: status %u',
           b'Initialization failed: %u', b'Failed to load profile', b'Failed to set bind',
           b'JNI_GetCreatedJavaVMs', b'SlinkyChannelHandler', b'Disabling hooks failed',
           b'slinky', b'status: %lu']

for nd in needles:
    hits = [m.start() for m in re.finditer(re.escape(nd), d)]
    print('%-28s %d %s' % (nd.decode(), len(hits), ' '.join('%08x' % h for h in hits[:10])))

print()
print('--- bytes at 0x13f800 ---')
print(d[0x13f800:0x13f840].hex())
