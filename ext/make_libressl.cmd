@echo off
set "EXT_LIB_DIR=%~dp0"

call set_out_path.cmd

set MS_BLD_LL=m
set MS_BLD_TOOLSET=v140
set VC_STATIC_RTL=1

set SLN_NAME="%EXT_LIB_DIR%\libressl-msvc\LibreSSL.sln"

set "LIBRESSL_SRC=%EXT_LIB_DIR%\libressl-msvc\src\"
del "%LIBRESSL_SRC%\include\openssl\opensslfeatures.h"
copy /y "%EXT_LIB_DIR%\opensslfeatures.h" "%LIBRESSL_SRC%\include\openssl\opensslfeatures.h"

set "MS_BLD_ARG=%SLN_NAME%"
set "MS_BLD_ARG=%MS_BLD_ARG% /m /verbosity:%MS_BLD_LL%"
set "MS_BLD_ARG=%MS_BLD_ARG% /p:PlatformToolset=%MS_BLD_TOOLSET%"
set "MS_BLD_ARG=%MS_BLD_ARG% /t:Clean,Build"
set "MS_BLD_ARG=%MS_BLD_ARG% /p:Platform=%MS_BLD_PLATFORM%"
set "MS_BLD_ARG=%MS_BLD_ARG% /p:UseFullPaths=False"

set MS_BLD_PLATFORM=Win32
call "%VS140COMNTOOLS%\vsvars32.bat"
msbuild %MS_BLD_ARG% /p:Configuration=Debug
msbuild %MS_BLD_ARG% /p:Configuration=Release

set MS_BLD_PLATFORM=x64
call "%VS140COMNTOOLS%..\..\VC\bin\x86_amd64\vcvarsx86_amd64.bat"
msbuild %MS_BLD_ARG% /p:Configuration=Debug
msbuild %MS_BLD_ARG% /p:Configuration=Release