Slinky
======

Minecraft 1.8.9 / Forge 11.15.1.2318 client.

Files
-----
  Slinky.exe        injector (loads slinky.dll into Minecraft)
  slinky.dll        client library
  slinky_run.ps1    one-step launch: starts the game, waits for the main menu,
                    then injects the client
  launch\           game libraries and the detached-process helper

Usage
-----
  powershell -NoProfile -ExecutionPolicy Bypass -File slinky_run.ps1

Or start Minecraft yourself and run:

  Slinky.exe

In game: Right Shift opens and closes the ClickGUI.

Compatibility
-------------
Built for vanilla/Forge Minecraft 1.8.9 using MCP, SRG or the original
obfuscated names. Lunar Client is not supported: it remaps class members and
the client will fail to initialise and unload itself.

Account
-------
The launcher reads Minecraft account values from a local file that is not part
of the repository:

  %USERPROFILE%\.slinky_account.bat

  set "MC_USER=YourName"
  set "MC_UUID=00000000000000000000000000000000"
  set "MC_TOKEN=0"

Without that file the launch script uses placeholder values and Minecraft
starts in offline mode. Point the script at your own install by editing the
$game, $jre and $version variables at the top of slinky_run.ps1.

Notes
-----
- Inject only after the main menu has fully loaded (the sound engine must be up).
  Injecting on the first window frame leaves game classes uninitialised and the
  client reports error 2004.
- If the game is already running, Slinky.exe finds it automatically.

Build
-----
  cd client
  cmake -S . -B build -G Ninja -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-windows-clang-cl.cmake
  cmake --build build

Requires clang-cl, lld-link, llvm-lib, llvm-dlltool and Ninja (LLVM for Windows).
The injector builds from client\injector.
