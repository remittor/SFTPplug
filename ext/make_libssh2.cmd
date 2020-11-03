@echo off
set "EXT_LIB_DIR=%~dp0"

call set_out_path.cmd

set MS_BLD_LL=m
set MS_BLD_TOOLSET=v140
set VC_STATIC_RTL=1

set SLN_NAME="%EXT_LIB_DIR%\libssh2-msvc\LibSSH2.sln"

set "LIBRESSL_SRC=%EXT_LIB_DIR%\libressl-msvc\src\"
set "OPENSSL_INC=%LIBRESSL_SRC%\include\"
set "OPENSSL_LIB=%GLB_OUT_LIB_DIR%"
set "LIBSSH2_SRC=%EXT_LIB_DIR%\libssh2\"
set "LIBSSH2_CFG_DIR=%EXT_LIB_DIR%\libssh2-msvc\msvc\"
copy /y "%EXT_LIB_DIR%\libssh2_cfg.h" "%LIBSSH2_CFG_DIR%\libssh2_cfg.h"
copy /y "%EXT_LIB_DIR%\libssh2_cfg.h" "%LIBSSH2_SRC%\include\libssh2_cfg.h"
copy /y "%LIBSSH2_CFG_DIR%\libssh2_config.h" "%LIBSSH2_SRC%\include\libssh2_config.h"

set MS_BLD_PLATFORM=Win32
call "%VS140COMNTOOLS%\vsvars32.bat"
msbuild %SLN_NAME% /m /verbosity:%MS_BLD_LL% /p:PlatformToolset=%MS_BLD_TOOLSET% /t:Clean,Build /p:Platform=%MS_BLD_PLATFORM% /p:Configuration=Debug
msbuild %SLN_NAME% /m /verbosity:%MS_BLD_LL% /p:PlatformToolset=%MS_BLD_TOOLSET% /t:Clean,Build /p:Platform=%MS_BLD_PLATFORM% /p:Configuration=Release
set MS_BLD_PLATFORM=x64
call "%VS140COMNTOOLS%..\..\VC\bin\x86_amd64\vcvarsx86_amd64.bat"
msbuild %SLN_NAME% /m /verbosity:%MS_BLD_LL% /p:PlatformToolset=%MS_BLD_TOOLSET% /t:Clean,Build /p:Platform=%MS_BLD_PLATFORM% /p:Configuration=Debug
msbuild %SLN_NAME% /m /verbosity:%MS_BLD_LL% /p:PlatformToolset=%MS_BLD_TOOLSET% /t:Clean,Build /p:Platform=%MS_BLD_PLATFORM% /p:Configuration=Release
