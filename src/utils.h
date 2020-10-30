#pragma once

#include "global.h"


/* String functions */

#define LoadStr(s, i)  LoadString(hinst, (i), (s), countof(s)-1)

LPSTR  strlcpy(LPSTR p, LPCSTR p2, size_t maxlen);
LPSTR  strlcat(LPSTR p, LPCSTR p2, size_t maxlen);
LPWSTR wcslcpy2(LPWSTR p, LPCWSTR p2, size_t maxlen);
LPSTR  strcatbackslash(LPSTR thedir);
LPSTR  strlcatforwardslash(LPSTR thedir, size_t maxlen);
LPSTR  strlcatbackslash(LPSTR thedir, size_t maxlen);
LPWSTR wcslcatbackslash(LPWSTR thedir, size_t maxlen);
void   cutlastbackslash(LPSTR thedir);
LPSTR  ReplaceBackslashBySlash(LPSTR thedir);
LPWSTR ReplaceBackslashBySlashW(LPWSTR thedir);
LPSTR  ReplaceSlashByBackslash(LPSTR thedir);
LPWSTR ReplaceSlashByBackslashW(LPWSTR thedir);


/* Time functions */

typedef INT64  SYSTICKS;

SYSTICKS get_sys_ticks() noexcept;

__forceinline
int get_ticks_between(SYSTICKS prev, SYSTICKS now)
{
    return (int)(now - prev);
}

__forceinline
int get_ticks_between(SYSTICKS prev)
{
    return get_ticks_between(prev, get_sys_ticks());
}

__forceinline
void SetInt64ToFileTime(FILETIME * ft, INT64 tm) noexcept
{
    INT64 * p = (INT64 *)ft;
    *p = tm;
}

bool ConvSysTimeToFileTime(const LPSYSTEMTIME st, LPFILETIME ft);
bool ConvertIsoDateToDateTime(LPCSTR pdatetimefield, LPFILETIME ft);
bool CreateIsoDateString(LPFILETIME ft, LPSTR buf); //yyyymmddhhmmss
bool UnixTimeToLocalTime(const time_t * mtime, LPFILETIME ft);


/* BASE64 */

int MimeEncodeData(LPCVOID indata, size_t inlen, LPSTR outstr, size_t maxlen);
int MimeEncode(LPCSTR inputstr, LPSTR outputstr, size_t maxlen);
int MimeDecode(LPCSTR inputstr, size_t inlen, LPVOID outdata, size_t maxlen);


/* String Formating */

void ReplaceEnvVars(LPSTR buf, size_t buflen);
void ReplaceSubString(LPSTR buf, LPCSTR fromstr, LPCSTR tostr, size_t maxlen);
bool ParseAddress(LPCSTR serverstring, LPSTR addr, WORD * port, int defport);
bool IsNumericIPv6(LPCSTR addr);

/* ======================== */

bool MultiFileMatchW(LPCWSTR wild, LPCWSTR name);


