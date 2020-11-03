#pragma once

#include "global.h"
#include <time.h>


#define FIN_IF(_cond_,_code_) do { if ((_cond_)) { hr = _code_; goto fin; } } while(0)
#define FIN(_code_)           do { hr = _code_; goto fin; } while(0)

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

__forceinline
timeval gettimeval(size_t milliseconds)
{
    timeval ret;
    ret.tv_sec = milliseconds / 1000;
    ret.tv_usec = (milliseconds % 1000) * 1000;
    return ret;
}

static const INT64 DELTA_EPOCH_IN_SECS = 11644473600LL;
static const INT   SECS_TO_100NANOSECS = 10000000L;
static const INT   WINDOWS_TICK = SECS_TO_100NANOSECS;

__forceinline void ConvUnixTimeToFileTime(LPFILETIME ft, INT64 utm)
{
    SetInt64ToFileTime(ft, utm * WINDOWS_TICK + (DELTA_EPOCH_IN_SECS * WINDOWS_TICK));
}

__forceinline
FILETIME GetFileTimeFromUnixTime(INT64 utm)
{
    FILETIME ret;
    ConvUnixTimeToFileTime(&ret, utm);
    return ret;
}

__forceinline
INT64 GetUnixTime64(INT64 ms_time)
{
    return (ms_time - DELTA_EPOCH_IN_SECS * WINDOWS_TICK) / WINDOWS_TICK;
} 

__forceinline
LONG GetUnixTime(const LPFILETIME ft)
{
    const INT64 ms_time = *(INT64 *)ft;
    if (ms_time <= DELTA_EPOCH_IN_SECS * WINDOWS_TICK)
        return 0;
    return (LONG)(GetUnixTime64(ms_time) & 0xFFFFFFFF);
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


