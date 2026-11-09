# Open Slinky

A readable C++ reconstruction of the **Slinky** client for **Minecraft 1.8.9** (Forge 11.15.1.2318).

The client is injected into the game's JVM as a native DLL. It attaches through JNI/JVMTI, rewrites
selected call sites in nine game classes while they are loaded, dispatches events to a module
system, and renders its ClickGUI and HUD overlay with NanoVG.

This repository contains the complete native source and a ready-to-run Windows build.

## Contents

| Path | What it is |
|---|---|
| `Slinky/` | Ready-to-run package: `Slinky.exe` injector, `slinky.dll`, one-step `slinky_run.ps1`, Forge launch jar and helper |
| `client/` | Source: engine (JVMTI/JNI, class hooks, GUI, module manager), module logic, data tables, platform layer, injector, docs |
| `client/docs/` | Design notes, symbol maps, module and mapping audits |
| `tools/` | Reverse-engineering and analysis helpers used during the reconstruction; not needed to build or run |

`client/README.md` covers the source layout, build prerequisites and the reconstruction notes.

## Quick start (prebuilt)

Requirements:

- Windows x64
- Minecraft 1.8.9 with Forge 11.15.1.2318 installed (defaults target the TLauncher
  `ForgeOptiFine 1.8.9` layout)
- The Java 8 runtime that launcher uses

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File Slinky\slinky_run.ps1
```

The script starts the game detached, waits until the main menu has fully loaded, then injects
`slinky.dll`. If the game is already running, `Slinky\Slinky.exe` finds it and injects directly.

**Right Shift** opens and closes the ClickGUI. Use the in-GUI **Unload** tab to unload the client.

## Account

No account data is stored in this repository. `slinky_run.ps1` reads optional values at run time from:

```
%USERPROFILE%\.slinky_account.bat
    set "MC_USER=YourName"
    set "MC_UUID=00000000000000000000000000000000"
    set "MC_TOKEN=0"
```

Without that file the game starts in offline mode with placeholder values. To use a different
install, edit `$game`, `$jre` and `$version` at the top of `Slinky/slinky_run.ps1`.

## Building the client

Requires LLVM for Windows (`clang-cl`, `lld-link`, `llvm-lib`, `llvm-dlltool`, `llvm-mt`),
CMake 3.20 or newer and Ninja. No Windows SDK is needed.

```powershell
cd client
cmake -S . -B build/cmake -G Ninja -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-windows-clang-cl.cmake
cmake --build build/cmake
```

Output: `client/build/cmake/slinky.dll` (copy it beside `Slinky.exe`).

The injector source is in `client/injector` (CMake; build with MinGW-w64 or MSVC). A prebuilt
`Slinky.exe` is included, so building it is optional.

## Supported game versions

| Game | Names | Status |
|---|---|---|
| 1.8.9 vanilla / Forge | MCP | Supported, tested |
| 1.8.9 vanilla / Forge | SRG | Supported |
| 1.8.9 vanilla | obfuscated (`ave`, ...) | Supported |
| 1.7.10 | obfuscated / MCP / SRG | Hook tables exist; not tested in this release |
| Lunar Client 1.8.9 | custom remap | **Not supported** |

The DLL recognizes only the mappings above. Lunar Client remaps class members and loads its own
transformers and protection; injection may succeed, but client initialization fails and the DLL
unloads itself. The launch script is configured for ForgeOptiFine 1.8.9 via TLauncher, not Lunar.

## How it works

1. `Slinky.exe` injects `slinky.dll` into the game process with `CreateRemoteThread(LoadLibraryW)`.
2. Start-up attaches to the JVM, finds the game's class loader, detects the name mapping and
   resolves the JNI ID table.
3. A JVMTI `ClassFileLoadHook` rewrites selected `invoke`/field instructions in nine game classes
   into calls to the client's natives; the classes are retransformed.
4. The native hooks build an event context and dispatch events to the module manager.
5. NanoVG renders the ClickGUI and the module overlay; settings and profiles are stored in
   `%USERPROFILE%\.slinky`.

## Notes and limitations

- This is a reconstruction: some protector-virtualised routines were reimplemented or inferred.
  `client/docs/` records what was recovered and what was not.
- Inject only after the main menu is up. Injecting on the first window frame leaves game classes
  uninitialised (error 2004).
- The binaries are unsigned; Windows SmartScreen may warn.
- Settings and profiles are written to `%USERPROFILE%\.slinky`.
- The scripts in `tools/` expect original-analysis files that are not shipped here
  (`packed.dll`, `solution\lib_beta_win_orig.dll`); they are kept for reference only.
- No account credentials, license keys, certificates or private keys are included.

## Credits

- Original client: Slinky
- Reconstruction: Claude (VMProtect devirtualization), DeepSeek (decryption), GLM and Claude
  (symbol recovery)
- Bundled third-party code: NanoVG (Mikko Mononen), stb (Sean Barrett), GL headers

## Legal & disclaimers

- **Affiliation:** This is an independent development. It is **NOT AN OFFICIAL SLINKY PRODUCT**, is
  not approved by or associated with the original authors, and is not affiliated with Mojang,
  Zelix Pty Ltd or Lunar Client.
- **Assets & code:** No un-obfuscated original source code is distributed directly within this
  repository. The `src/data` tables are the client's own data required for linking; all third-party
  assets and code belong to their respective owners.
- **Purpose:** research and preservation. Use at your own risk.
