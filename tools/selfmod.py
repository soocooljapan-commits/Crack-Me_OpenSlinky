import ctypes, sys
from ctypes import wintypes

PATH = r'C:\Users\user\Pictures\crm\packed.dll'
KEY = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345'

k32 = ctypes.WinDLL('kernel32')
dll = ctypes.CDLL(PATH)
base = ctypes.cast(dll._handle, ctypes.c_void_p).value
print('base', hex(base), flush=True)

before = ctypes.string_at(base + 0x1290, 0x200)
open('before1290.bin', 'wb').write(before)
print('before', before[:64].hex(), flush=True)

FN = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_wchar_p)
print('call', FN(base + 0x1000)(KEY), flush=True)

after = ctypes.string_at(base + 0x1290, 0x200)
open('after1290.bin', 'wb').write(after)
print('after ', after[:64].hex(), flush=True)
print('diff', [(hex(0x1290 + i), before[i], after[i]) for i in range(0x200) if before[i] != after[i]][:40], flush=True)

# also dump 0x1000 and 0x133d50c
open('after1000.bin', 'wb').write(ctypes.string_at(base + 0x1000, 0x1200))
open('aftervm.bin', 'wb').write(ctypes.string_at(base + 0x133d50c, 0x400))
