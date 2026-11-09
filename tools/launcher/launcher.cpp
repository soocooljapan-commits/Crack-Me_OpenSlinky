// launcher.exe <bat> <log>  - start a console program outside the caller's console and job object
#include <windows.h>
#include <stdio.h>

int wmain(int argc, wchar_t **argv)
{
    if (argc < 3) { wprintf(L"usage: launcher.exe <bat> <log>\n"); return 2; }
    wchar_t cmd[32768];
    _snwprintf(cmd, 32768, L"cmd.exe /c \"\"%s\" > \"%s\" 2>&1\"", argv[1], argv[2]);

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    DWORD flags = CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB | CREATE_NEW_PROCESS_GROUP;
    if (!CreateProcessW(0, cmd, 0, 0, FALSE, flags, 0, 0, &si, &pi)) {
        DWORD e = GetLastError();
        flags &= ~CREATE_BREAKAWAY_FROM_JOB;
        if (!CreateProcessW(0, cmd, 0, 0, FALSE, flags, 0, 0, &si, &pi)) {
            wprintf(L"CreateProcess failed: %lu\n", e); return 1;
        }
        wprintf(L"breakaway denied, started without it\n");
    }
    wprintf(L"started pid %lu\n", pi.dwProcessId);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
