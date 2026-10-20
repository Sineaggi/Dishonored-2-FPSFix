@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

where cl.exe >nul 2>nul
if errorlevel 1 (
  set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
  if not exist "!VSWHERE!" (
    echo Microsoft C++ Build Tools were not found.
    echo Install Visual Studio Build Tools with Desktop development with C++.
    exit /b 1
  )

  set "VSINSTALL="
  for /f "usebackq tokens=*" %%I in (`"!VSWHERE!" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSINSTALL=%%I"
  if not defined VSINSTALL (
    echo The Visual Studio x64 C++ toolchain was not found.
    exit /b 1
  )
  call "!VSINSTALL!\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64
  if errorlevel 1 exit /b 1
)

if not exist "build" mkdir "build"

cl.exe /nologo /std:c++17 /O2 /EHsc /W4 /LD /DUNICODE /D_UNICODE ^
  /Fo:"build\d2-high-fps-fix.obj" ^
  "d2_high_fps_fix.cpp" ^
  /link /OUT:"build\Dishonored2HighFPSFix.asi" bcrypt.lib user32.lib gdi32.lib

if errorlevel 1 (
  echo.
  echo Build failed.
  exit /b 1
)

cl.exe /nologo /std:c++17 /O2 /EHsc /W4 /DUNICODE /D_UNICODE ^
  /Fo:"build\asi-load-test.obj" ^
  "asi-load-test.cpp" ^
  /link /OUT:"build\asi-load-test.exe"

if errorlevel 1 (
  echo.
  echo ASI load-test build failed.
  exit /b 1
)

if not exist "build\layout-host" mkdir "build\layout-host"
copy /Y "build\asi-load-test.exe" "build\layout-host\Dishonored2.exe" >nul
if errorlevel 1 (
  echo.
  echo Layout-host test staging failed.
  exit /b 1
)

cl.exe /nologo /std:c++17 /O2 /EHsc /W4 /DUNICODE /D_UNICODE ^
  /Fo:"build\asi-loader-test.obj" ^
  "asi-loader-test.cpp" ^
  /link /OUT:"build\asi-loader-test.exe" dinput8.lib dxguid.lib

if errorlevel 1 (
  echo.
  echo External ASI loader integration-test build failed.
  exit /b 1
)

cl.exe /nologo /std:c++17 /O2 /EHsc /W4 ^
  /Fo:"build\\joint-pose-test.obj" ^
  "joint-pose-test.cpp" ^
  /link /OUT:"build\joint-pose-test.exe"

if errorlevel 1 (
  echo.
  echo Joint-pose interpolation test build failed.
  exit /b 1
)

"build\joint-pose-test.exe"
if errorlevel 1 (
  echo.
  echo Joint-pose interpolation tests failed.
  exit /b 1
)

"build\asi-load-test.exe" "build\Dishonored2HighFPSFix.asi"
if errorlevel 1 (
  echo.
  echo ASI load test failed.
  exit /b 1
)

"build\layout-host\Dishonored2.exe" "build\Dishonored2HighFPSFix.asi" --layout-host
if errorlevel 1 (
  echo.
  echo Executable-layout fail-closed test failed.
  exit /b 1
)

echo.
echo Built and load-tested: %CD%\build\Dishonored2HighFPSFix.asi
echo Built: %CD%\build\asi-load-test.exe
echo Built: %CD%\build\asi-loader-test.exe
echo Built and passed: %CD%\build\joint-pose-test.exe
endlocal
