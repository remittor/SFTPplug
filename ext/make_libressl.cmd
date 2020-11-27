@echo off
set "EXT_LIB_DIR=%~dp0"

call set_out_path.cmd

set MS_BLD_LL=m
set MS_BLD_TOOLSET=v140
set VC_STATIC_RTL=1

set SLN_NAME="libressl-msvc\LibreSSL.sln"

set "LIBRESSL_SRC=%EXT_LIB_DIR%\libressl-msvc\src\"
del "%LIBRESSL_SRC%\include\openssl\opensslfeatures.h"
copy /y "%EXT_LIB_DIR%\opensslfeatures.h" "%LIBRESSL_SRC%\include\openssl\opensslfeatures.h"

set GLB_FAKE_DEBUG=1
rem /Od = Disabled /O1 = MinSpace /O2 = MaxSpeed /Ox = Full
set GLB_FAKE_DEBUG_OPT=Full
rem Inline: Disabled / Default
set GLB_FAKE_DEBUG_INL=Default

set "MS_BLD_ARGX=/m"
set "MS_BLD_ARGX=%MS_BLD_ARGX% /verbosity:%MS_BLD_LL%"
set "MS_BLD_ARGX=%MS_BLD_ARGX% /p:PlatformToolset=%MS_BLD_TOOLSET%"
set "MS_BLD_ARGX=%MS_BLD_ARGX% /t:Clean,Build"
set "MS_BLD_ARGX=%MS_BLD_ARGX% /p:UseFullPaths=False"

set "MS_BLD_ARG=%EXT_LIB_DIR%\%SLN_NAME% %MS_BLD_ARGX%"

set MS_BLD_PLATFORM=Win32
call "%VS140COMNTOOLS%\vsvars32.bat"
msbuild %MS_BLD_ARG% /p:Platform=%MS_BLD_PLATFORM% /p:Configuration=Debug
msbuild %MS_BLD_ARG% /p:Platform=%MS_BLD_PLATFORM% /p:Configuration=Release

set MS_BLD_PLATFORM=x64
call "%VS140COMNTOOLS%..\..\VC\bin\x86_amd64\vcvarsx86_amd64.bat"
msbuild %MS_BLD_ARG% /p:Platform=%MS_BLD_PLATFORM% /p:Configuration=Debug
msbuild %MS_BLD_ARG% /p:Platform=%MS_BLD_PLATFORM% /p:Configuration=Release
