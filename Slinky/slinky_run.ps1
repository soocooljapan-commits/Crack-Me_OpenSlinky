# Slinky - launch Minecraft and inject the client.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File slinky_run.ps1
#
# The game is started detached with its console output discarded. The injector
# waits until the game has finished loading (main menu), then loads slinky.dll.
# In game: Right Shift opens and closes the ClickGUI.
$ErrorActionPreference = 'Stop'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$log = Join-Path $env:APPDATA '.tlauncher\legacy\Minecraft\game\logs\latest.log'

# ---- game / account configuration ----
$game = Join-Path $env:APPDATA '.tlauncher\legacy\Minecraft\game'
$jre = Join-Path $env:APPDATA '.tlauncher\legacy\Minecraft\jre\jre-legacy\windows-x64\jre-legacy\bin\java.exe'
$version = 'ForgeOptiFine 1.8.9'
$accountFile = Join-Path $env:USERPROFILE '.slinky_account.bat'

$libraries = @(
    'net\minecraft\launchwrapper\1.12\launchwrapper-1.12.jar'
    'org\ow2\asm\asm-all\5.0.3\asm-all-5.0.3.jar'
    'jline\jline\2.13\jline-2.13.jar'
    'com\typesafe\akka\akka-actor_2.11\2.3.3\akka-actor_2.11-2.3.3.jar'
    'com\typesafe\config\1.2.1\config-1.2.1.jar'
    'org\scala-lang\scala-actors-migration_2.11\1.1.0\scala-actors-migration_2.11-1.1.0.jar'
    'org\scala-lang\scala-compiler\2.11.1\scala-compiler-2.11.1.jar'
    'org\scala-lang\plugins\scala-continuations-library_2.11\1.0.2\scala-continuations-library_2.11-1.0.2.jar'
    'org\scala-lang\plugins\scala-continuations-plugin_2.11.1\1.0.2\scala-continuations-plugin_2.11.1-1.0.2.jar'
    'org\scala-lang\scala-library\2.11.1\scala-library-2.11.1.jar'
    'org\scala-lang\scala-parser-combinators_2.11\1.0.1\scala-parser-combinators_2.11-1.0.1.jar'
    'org\scala-lang\scala-reflect\2.11.1\scala-reflect-2.11.1.jar'
    'org\scala-lang\scala-swing_2.11\1.0.1\scala-swing_2.11-1.0.1.jar'
    'org\scala-lang\scala-xml_2.11\1.0.2\scala-xml_2.11-1.0.2.jar'
    'lzma\lzma\0.0.1\lzma-0.0.1.jar'
    'net\sf\jopt-simple\jopt-simple\4.6\jopt-simple-4.6.jar'
    'java3d\vecmath\1.5.2\vecmath-1.5.2.jar'
    'net\sf\trove4j\trove4j\3.0.3\trove4j-3.0.3.jar'
    'com\mojang\netty\1.8.8\netty-1.8.8.jar'
    'oshi-project\oshi-core\1.1\oshi-core-1.1.jar'
    'net\java\dev\jna\jna\3.4.0\jna-3.4.0.jar'
    'net\java\dev\jna\platform\3.4.0\platform-3.4.0.jar'
    'com\ibm\icu\icu4j-core-mojang\51.2\icu4j-core-mojang-51.2.jar'
    'com\paulscode\codecjorbis\20101023\codecjorbis-20101023.jar'
    'com\paulscode\codecwav\20101023\codecwav-20101023.jar'
    'com\paulscode\libraryjavasound\20101123\libraryjavasound-20101123.jar'
    'com\paulscode\librarylwjglopenal\20100824\librarylwjglopenal-20100824.jar'
    'com\paulscode\soundsystem\20120107\soundsystem-20120107.jar'
    'io\netty\netty-all\4.0.23.Final\netty-all-4.0.23.Final.jar'
    'com\google\guava\guava\17.0\guava-17.0.jar'
    'org\apache\commons\commons-lang3\3.3.2\commons-lang3-3.3.2.jar'
    'commons-io\commons-io\2.4\commons-io-2.4.jar'
    'commons-codec\commons-codec\1.9\commons-codec-1.9.jar'
    'net\java\jinput\jinput\2.0.5\jinput-2.0.5.jar'
    'net\java\jutils\jutils\1.0.0\jutils-1.0.0.jar'
    'com\google\code\gson\gson\2.2.4\gson-2.2.4.jar'
    'com\mojang\authlib\1.5.21\authlib-1.5.21.jar'
    'com\mojang\realms\1.7.59\realms-1.7.59.jar'
    'org\apache\commons\commons-compress\1.8.1\commons-compress-1.8.1.jar'
    'org\apache\httpcomponents\httpclient\4.3.3\httpclient-4.3.3.jar'
    'commons-logging\commons-logging\1.1.3\commons-logging-1.1.3.jar'
    'org\apache\httpcomponents\httpcore\4.3.2\httpcore-4.3.2.jar'
    'org\apache\logging\log4j\log4j-api\2.0-beta9\log4j-api-2.0-beta9.jar'
    'org\apache\logging\log4j\log4j-core\2.0-beta9\log4j-core-2.0-beta9.jar'
    'org\lwjgl\lwjgl\lwjgl\2.9.4-nightly-20150209\lwjgl-2.9.4-nightly-20150209.jar'
    'org\lwjgl\lwjgl\lwjgl_util\2.9.4-nightly-20150209\lwjgl_util-2.9.4-nightly-20150209.jar'
    'tv\twitch\twitch\6.5\twitch-6.5.jar'
)
$classpath = (@((Join-Path $dir 'launch\forge-2318-unsigned.jar')) +
              ($libraries | ForEach-Object { Join-Path $game (Join-Path 'libraries' $_) }) +
              @((Join-Path $game "versions\$version\$version.jar"))) -join ';'
$natives = Join-Path $game "versions\$version\natives"
$clientJar = Join-Path $game "versions\$version\$version.jar"
$log4j = Join-Path $game 'assets\log_configs\patched-variant-2.0.xml'

# The launch script is generated next to this file and removed once the game is
# up. Account values are not copied into it: it reads %USERPROFILE%\.slinky_account.bat
# at run time (placeholder offline values when that file is absent).
$tempBat = Join-Path $dir 'launch\.slinky_launch.tmp.bat'
$launchBat = @'
@echo off
setlocal
set "GAME=@GAME@"
set "JRE=@JRE@"
set "VERSION=@VERSION@"
set "MC_USER=Player"
set "MC_UUID=00000000000000000000000000000000"
set "MC_TOKEN=0"
if exist "%USERPROFILE%\.slinky_account.bat" call "%USERPROFILE%\.slinky_account.bat"
cd /d "%GAME%"
set "CLASSPATH=@CLASSPATH@"
"%JRE%" -Xms892M -XX:+UnlockExperimentalVMOptions -XX:+DisableExplicitGC -XX:MaxGCPauseMillis=50 -XX:+AlwaysPreTouch -XX:+ParallelRefProcEnabled -XX:+UseG1GC -XX:G1NewSizePercent=20 -XX:G1MaxNewSizePercent=40 -XX:G1HeapRegionSize=8M -XX:G1ReservePercent=20 -XX:InitiatingHeapOccupancyPercent=15 -XX:G1HeapWastePercent=5 -XX:G1MixedGCCountTarget=4 -XX:G1MixedGCLiveThresholdPercent=90 -XX:G1RSetUpdatingPauseTimePercent=5 -XX:+UseStringDeduplication -XX:MaxTenuringThreshold=1 -XX:SurvivorRatio=32 -Xmx2048M -Dfile.encoding=UTF-8 "-Dlog4j.configurationFile=@LOG4J@" -Dfml.ignoreInvalidMinecraftCertificates=true -Dfml.ignorePatchDiscrepancies=true -Djava.net.useSystemProxies=true "-Dos.name=Windows 10" -Dos.version=10.0 "-Djava.library.path=@NATIVES@" -Dminecraft.launcher.brand=java-minecraft-launcher -Dminecraft.launcher.version=1.6.84-j "-Dminecraft.client.jar=@CLIENTJAR@" -Xss2M net.minecraft.launchwrapper.Launch --username %MC_USER% --version "%VERSION%" --gameDir "%GAME%" --assetsDir "%GAME%\assets" --assetIndex 1.8 --uuid %MC_UUID% --accessToken %MC_TOKEN% --userProperties {} --userType legacy --tweakClass net.minecraftforge.fml.common.launcher.FMLTweaker --width 925 --height 530
echo EXITCODE=%ERRORLEVEL%
endlocal
'@
$launchBat = $launchBat.Replace('@GAME@', $game).Replace('@JRE@', $jre).Replace('@VERSION@', $version).
    Replace('@CLASSPATH@', $classpath).Replace('@LOG4J@', $log4j).Replace('@NATIVES@', $natives).Replace('@CLIENTJAR@', $clientJar)
Set-Content -Path $tempBat -Value $launchBat -Encoding Ascii

Get-Process java, javaw -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Remove-Item $log -Force -ErrorAction SilentlyContinue

& "$dir\launch\launcher.exe" "$tempBat" NUL | Out-Null

$p = $null
for ($i = 0; $i -lt 90; $i++) {
    Start-Sleep -Seconds 2
    $p = Get-Process java -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($p -and $p.MainWindowTitle -match 'Minecraft') { break }
}
Remove-Item $tempBat -Force -ErrorAction SilentlyContinue
if (-not $p) { throw "game window never appeared" }

# The client needs the game's classes initialised. Injecting on the first
# window frame poisons them, so wait for the sound engine (main menu) line.
$ready = $false
for ($i = 0; $i -lt 60; $i++) {
    if ((Test-Path $log) -and (Select-String -Path $log -Pattern 'Sound engine started' -Quiet -ErrorAction SilentlyContinue)) { $ready = $true; break }
    Start-Sleep -Seconds 2
}
if (-not $ready) { Start-Sleep -Seconds 20 }
Start-Sleep -Seconds 5

& "$dir\Slinky.exe" --no-anim 2>&1 | Out-Null
Start-Sleep -Seconds 2

"pid=$($p.Id)"
"loaded - right shift opens the GUI"
