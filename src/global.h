#pragma once

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NON_CONFORMING_SWPRINTFS

/* Disable WinSock.h and wsock32.lib */
#define _WINSOCKAPI_

#include <windows.h>
#include <BaseTsd.h>
#include <stdlib.h>
#include <stdio.h>
#include <shlwapi.h>
#include <ws2tcpip.h>

#ifndef RESOURCE_ENUM_VALIDATE
#error "Please, update Microsoft SDKs to 6.1 or later"
#endif

#ifndef _LPCBYTE_DEFINED
#define _LPCBYTE_DEFINED
typedef const BYTE *LPCBYTE;
#endif
#ifndef _LPCVOID_DEFINED
#define _LPCVOID_DEFINED
typedef const VOID *LPCVOID;
#endif

#ifndef countof
#define countof(array) (sizeof(array) / sizeof(array[0]))
#endif

#ifndef _itoa_s
#define _itoa_s(nr,buf,sz,rdx)  _itoa((nr),(buf),(rdx))
#endif

#ifdef WFX_DEBUG
#define BST_MAX_LOG_LEVEL   BST_LL_TRACE
#else
#define BST_MAX_LOG_LEVEL   BST_LL_WARNING
#endif

#ifdef __cplusplus
#include "fsplugin.h"
#include "bst/bst.hpp"
#include "bst/log.hpp"
#include "bst/string.hpp"
#include "bst/list.hpp"
#include "bst/scope_guard.hpp"
#endif


