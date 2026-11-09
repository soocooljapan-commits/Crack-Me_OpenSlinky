import ctypes, sys, os
from ctypes import wintypes

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

EXCEPTION_DEBUG_EVENT = 1
EXCEPTION_CONTINUE_SEARCH = 0


class EXCEPTION_RECORD(ctypes.Structure):
    pass


EXCEPTION_RECORD._fields_ = [
    ('ExceptionCode', wintypes.DWORD),
    ('ExceptionFlags', wintypes.DWORD),
    ('ExceptionRecord', ctypes.POINTER(EXCEPTION_RECORD)),
    ('ExceptionAddress', ctypes.c_void_p),
    ('NumberParameters', wintypes.DWORD),
    ('ExceptionInformation', ctypes.c_void_p * 15),
]


class CONTEXT(ctypes.Structure):
    _fields_ = [
        ('P1Home', ctypes.c_uint64), ('P2Home', ctypes.c_uint64), ('P3Home', ctypes.c_uint64),
        ('P4Home', ctypes.c_uint64), ('P5Home', ctypes.c_uint64), ('P6Home', ctypes.c_uint64),
        ('ContextFlags', wintypes.DWORD), ('MxCsr', wintypes.DWORD),
        ('SegCs', wintypes.WORD), ('SegDs', wintypes.WORD), ('SegEs', wintypes.WORD),
        ('SegFs', wintypes.WORD), ('SegGs', wintypes.WORD), ('SegSs', wintypes.WORD),
        ('EFlags', wintypes.DWORD),
        ('Dr0', ctypes.c_uint64), ('Dr1', ctypes.c_uint64), ('Dr2', ctypes.c_uint64), ('Dr3', ctypes.c_uint64),
        ('Dr6', ctypes.c_uint64), ('Dr7', ctypes.c_uint64),
        ('Rax', ctypes.c_uint64), ('Rcx', ctypes.c_uint64), ('Rdx', ctypes.c_uint64), ('Rbx', ctypes.c_uint64),
        ('Rsp', ctypes.c_uint64), ('Rbp', ctypes.c_uint64), ('Rsi', ctypes.c_uint64), ('Rdi', ctypes.c_uint64),
        ('R8', ctypes.c_uint64), ('R9', ctypes.c_uint64), ('R10', ctypes.c_uint64), ('R11', ctypes.c_uint64),
        ('R12', ctypes.c_uint64), ('R13', ctypes.c_uint64), ('R14', ctypes.c_uint64), ('R15', ctypes.c_uint64),
        ('Rip', ctypes.c_uint64),
    ]


class EXCEPTION_POINTERS(ctypes.Structure):
    _fields_ = [('ExceptionRecord', ctypes.POINTER(EXCEPTION_RECORD)),
                ('ContextRecord', ctypes.POINTER(CONTEXT))]


@ctypes.WINFUNCTYPE(wintypes.LONG, ctypes.POINTER(EXCEPTION_POINTERS))
def handler(info):
    rec = info.contents.ExceptionRecord.contents
    ctx = info.contents.ContextRecord.contents
    print('EXCEPTION code=%08x addr=%x rip=%x' % (rec.ExceptionCode, rec.ExceptionAddress or 0, ctx.Rip), flush=True)
    print(' rax=%x rbx=%x rcx=%x rdx=%x rsi=%x rdi=%x rsp=%x rbp=%x' % (
        ctx.Rax, ctx.Rbx, ctx.Rcx, ctx.Rdx, ctx.Rsi, ctx.Rdi, ctx.Rsp, ctx.Rbp), flush=True)
    print(' r8=%x r9=%x r10=%x r11=%x r12=%x r13=%x r14=%x r15=%x' % (
        ctx.R8, ctx.R9, ctx.R10, ctx.R11, ctx.R12, ctx.R13, ctx.R14, ctx.R15), flush=True)
    if rec.NumberParameters:
        print(' params', [rec.ExceptionInformation[i] for i in range(rec.NumberParameters)], flush=True)
    os._exit(3)


kernel32.AddVectoredExceptionHandler(1, handler)

path = sys.argv[1]
key = sys.argv[2] if len(sys.argv) > 2 else None
if key:
    os.environ['SLINKY_LICENSE'] = key
print('loading', path, flush=True)
dll = ctypes.CDLL(path)
print('loaded', flush=True)
if key:
    fn = dll.slinky_init
    fn.argtypes = [ctypes.c_wchar_p]
    fn.restype = ctypes.c_int
    print('call ret', fn(key), flush=True)
import time
time.sleep(1)
print('ok', flush=True)
