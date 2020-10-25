#pragma once

#define falink 64   // Flag for link

BOOL ReadDirLineUNIX(WCHAR* lpStr, WCHAR* thename, int maxlen, __int64* sizefile, FILETIME* datetime,
                     DWORD* attr, DWORD* UnixAttr, BOOL longdatetype);

