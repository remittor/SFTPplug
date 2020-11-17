#include "utils.h"
#include <time.h>
#include <stdio.h>
#include <intrin.h>

LPSTR strcatbackslash(LPSTR thedir)
{
    if (thedir[0])
        if (thedir[strlen(thedir)-1] != '\\')
            strcat(thedir,  "\\");
    return thedir;
}

LPSTR strlcatforwardslash(LPSTR thedir, size_t maxlen)
{
    if (thedir[0])
        if (thedir[strlen(thedir)-1] != '/')
            strlcat(thedir, "/", maxlen);
    return thedir;
}

LPSTR strlcatbackslash(LPSTR thedir, size_t maxlen)
{
    if (thedir[0] && strlen(thedir) < maxlen)
        if (thedir[strlen(thedir)-1] != '\\')
            strlcat(thedir, "\\", maxlen);
    return thedir;
}

LPWSTR wcslcatbackslash(LPWSTR thedir, size_t maxlen)
{
    if (thedir[0] && wcslen(thedir) < maxlen)
        if (thedir[wcslen(thedir)-1] != '\\')
            wcsncat(thedir, L"\\", maxlen);
    return thedir;
}

void cutlastbackslash(LPSTR thedir)
{
    int len = strlen(thedir);
    if (len && thedir[len - 1] == '\\')
        thedir[len - 1] = 0;
}

LPSTR strlcpy(LPSTR p, LPCSTR p2, size_t maxlen)
{
    if (strlen(p2) >= maxlen) {
        strncpy(p, p2, maxlen);
        p[maxlen] = 0;
    } else {
        strcpy(p, p2);
    }
    return p;
}

LPWSTR wcslcpy2(LPWSTR p, LPCWSTR p2, size_t maxlen)
{
    if (wcslen(p2) >= maxlen) {
        wcsncpy(p, p2, maxlen);
        p[maxlen] = 0;
    } else {
        wcscpy(p, p2);
    }
    return p;
}

//strlcat is different from strncat:
//strncat wants maximum number of bytes to copy
//strlcat wants maximum size of target buffer!!!
LPSTR strlcat(LPSTR p, LPCSTR p2, size_t maxlen)
{
    return strncat(p, p2, maxlen - strlen(p));
}

LPSTR ReplaceBackslashBySlash(LPSTR thedir)
{
    for (LPSTR p = thedir; *p != 0; p++) {
        if (*p == '\\')
            *p = '/';
    }
    return thedir;
}

LPWSTR ReplaceBackslashBySlashW(LPWSTR thedir)
{
    for (LPWSTR p = thedir; *p != 0; p++) {
        if (*p == L'\\')
            *p = L'/';
    }
    return thedir;
}

LPSTR ReplaceSlashByBackslash(LPSTR thedir)
{
    for (LPSTR p = thedir; *p != 0; p++) {
        if (*p == '/')
            *p = '\\';
    }
    return thedir;
}

LPWSTR ReplaceSlashByBackslashW(LPWSTR thedir)
{
    for (LPWSTR p = thedir; *p != 0; p++) {
        if (*p == L'/')
            *p = L'\\';
    }
    return thedir;
}


typedef UINT64 (WINAPI * tGetTickCount64) (void);
tGetTickCount64  fnGetTickCount64 = NULL;
bool g_sys_ticks_inited = false;
LARGE_INTEGER g_sys_ticks_prev = {0};
LONG g_sys_tick_lock = 0;

SYSTICKS get_sys_ticks() noexcept
{
    if (!g_sys_ticks_inited) {
        while (_InterlockedCompareExchange(&g_sys_tick_lock, 1, 0) == 1);
        if (!g_sys_ticks_inited) {
            HMODULE kernel32 = GetModuleHandleA("kernel32");
            if (kernel32)
                fnGetTickCount64 = (tGetTickCount64) GetProcAddress(kernel32, "GetTickCount64");
            g_sys_ticks_inited = true;
        }
        _InterlockedExchange(&g_sys_tick_lock, 0);
    }

    if (fnGetTickCount64)
        return (SYSTICKS)fnGetTickCount64();

    const DWORD ticks = GetTickCount();
    if (ticks < g_sys_ticks_prev.LowPart) {
        while (_InterlockedCompareExchange(&g_sys_tick_lock, 1, 0) == 1);
        if (ticks < g_sys_ticks_prev.LowPart) {
            g_sys_ticks_prev.LowPart = ticks;
            g_sys_ticks_prev.HighPart++;
        }
        _InterlockedExchange(&g_sys_tick_lock, 0);
    }
    g_sys_ticks_prev.LowPart = ticks;
    return (SYSTICKS)g_sys_ticks_prev.QuadPart | ticks;
}

bool ConvSysTimeToFileTime(const LPSYSTEMTIME st, LPFILETIME ft)
{
    FILETIME tmp;
    SYSTEMTIME s = *st;
    if (s.wYear < 300)
        s.wYear += 1900;
    s.wDayOfWeek = 0;
    s.wMilliseconds = 0;
    if (SystemTimeToFileTime(&s, &tmp)) {
        BOOL rc = LocalFileTimeToFileTime(&tmp, ft);   // Totalcmd expects system time!
        return rc ? true : false;
    }
    SetInt64ToFileTime(ft, FS_TIME_UNKNOWN);
    return false;
}

static int conv2bytes(LPCSTR p)
{
    char buf[16];
    strlcpy(buf, p, 2);
    return atoi(buf);
}

bool ConvertIsoDateToDateTime(LPCSTR pdatetimefield, LPFILETIME ft)
{
    SYSTEMTIME st;
    char buf[16];
    strlcpy(buf, pdatetimefield, 4);
    st.wYear   = atoi(buf);
    st.wMonth  = conv2bytes(pdatetimefield + 4);
    st.wDay    = conv2bytes(pdatetimefield + 6);
    st.wHour   = conv2bytes(pdatetimefield + 8);
    st.wMinute = conv2bytes(pdatetimefield + 10);
    st.wSecond = conv2bytes(pdatetimefield + 12);
    return ConvSysTimeToFileTime(&st, ft);
}

bool UnixTimeToLocalTime(const time_t * mtime, LPFILETIME ft)
{
    struct tm* fttm = gmtime(mtime);
    SYSTEMTIME st;
    st.wYear   = fttm->tm_year;
    st.wMonth  = fttm->tm_mon + 1;  // 0-11 in struct tm*
    st.wDay    = fttm->tm_mday;
    st.wHour   = fttm->tm_hour;
    st.wMinute = fttm->tm_min;
    st.wSecond = fttm->tm_sec;
    return ConvSysTimeToFileTime(&st, ft);
}

void Conv2Chars(LPSTR buf, int nr)
{
    if (nr <= 9) {
        buf[0] = '0';
        buf[1] = '0' + nr;
    } else {
        _itoa(nr, buf, 10);
    }
}

bool CreateIsoDateString(LPFILETIME ft, LPSTR buf)
{
    FILETIME ft2;
    buf[0] = 0;
    if (FileTimeToLocalFileTime(ft, &ft2) == FALSE)
        return false;
    SYSTEMTIME dt;
    if (FileTimeToSystemTime(&ft2, &dt) == FALSE)
        return false;
    int rc = sprintf(buf, "%04u%02u%02u%02u%02u", dt.wYear, dt.wDay, dt.wHour, dt.wMinute, dt.wSecond);
    return (rc > 0) ? true : false;
}


const char MimeTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

__forceinline
static char EncodeMIME(UCHAR ch)
{
    return MimeTable[ch & 0x3F];
}

__forceinline
static void EncodeMimeTriple(LPCBYTE inbuf, size_t j, LPSTR outbuf)
{
    BYTE c1, c2, c3, c4;
    c1  = (inbuf[0] >> 2);
    c2  = (inbuf[0] << 4) & 0x30;
    c2 |= (inbuf[1] >> 4) & 0x0F;
    c3  = (inbuf[1] << 2) & 0x3C;
    c3 |= (inbuf[2] >> 6) & 0x03;
    c4  = (inbuf[2]     ) & 0x3F;
    outbuf[0] = EncodeMIME(c1);
    outbuf[1] = EncodeMIME(c2);
    outbuf[2] = (j > 1) ? EncodeMIME(c3) : '=';   // Last char padding
    outbuf[3] = (j > 2) ? EncodeMIME(c4) : '=';
    outbuf[4] = 0;
}

int MimeEncodeData(LPCVOID indata, size_t inlen, LPSTR outstr, size_t maxlen)
{
    char buf[8];
    outstr[0] = 0;
    LPCBYTE p = (LPCBYTE)indata;
    for (SSIZE_T j = inlen; j > 0; j -= 3) {
        EncodeMimeTriple(p, j, buf);
        p += 3;
        strlcat(outstr, buf, maxlen);
    }
    return (int)strlen(outstr);
}

int MimeEncode(LPCSTR inputstr, LPSTR outputstr, size_t maxlen)
{
    return MimeEncodeData(inputstr, strlen(inputstr), outputstr, maxlen);
}

static const char base64_reverse_table[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

int MimeDecode(LPCSTR indata, size_t inlen, LPVOID outdata, size_t maxlen)
{
    LPBYTE d = (LPBYTE)outdata;
    LPBYTE const end = d + maxlen;
    for (size_t i = 0; i < inlen; i++) {
        const BYTE v = (BYTE)base64_reverse_table[indata[i]];
        if ((char)v >= 0) {
            switch (i & 3) {
            case 0:
                *d = v << 2;
                break;
            case 1:
                *d++ |= v >> 4;
                *d = v << 4;
                break;
            case 2:
                *d++ |= v >> 2;
                *d = v << 6;
                break;
            case 3:
                *d++ |= v;
                break;
            }
            if (d >= end)
                break;
        }
    }
    return (int)((size_t)d - (size_t)outdata);
}


// Replace %name% by environment variable
void ReplaceEnvVars(LPSTR buf, size_t buflen)
{
    char buf2[2*1024];  /* FIXME: remove size limit */
    char envname[MAX_PATH];
    char envbuf[MAX_PATH];
    while (1) {
        LPSTR p = strchr(buf, '%');
        if (!p)
            break;
        if (p[1] == '%')
            break;   // found %%
        LPSTR p1 = strchr(p + 1, '%');
        if (!p1)
            break;
        p1[0] = 0;
        strcpy(envname, p + 1);
        p1[0] = '%';
        DWORD len = GetEnvironmentVariableA(envname, envbuf, sizeof(envbuf));
        /* FIXME: check GetLastError()
           https://docs.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getenvironmentvariablea#return-value */
        if (len) {
            envbuf[sizeof(envbuf)-1] = 0;
            p[0] = 0;
            strlcpy(buf2, buf, sizeof(buf2)-1);
            strlcat(buf2, envbuf, sizeof(buf2)-1);
            strlcat(buf2, p1 + 1, sizeof(buf2)-1);
            strlcpy(buf, buf2, buflen);
        }
    }
}

void ReplaceSubString(LPSTR buf, LPCSTR fromstr, LPCSTR tostr, size_t maxlen)
{
    char buf2[2*1024];   /* FIXME: remove size limit */
    size_t L = strlen(fromstr);
    if (L == 0)  // nothing to do
        return;
    size_t L2 = strlen(tostr);
    LPSTR p = buf;
    while (*p) {
        if (*p == fromstr[0] && strncmp(p, fromstr, L) == 0) {
            *p = 0;
            strlcpy(buf2, p + L, sizeof(buf2)-1);    // save rest of string
            strlcat(buf, tostr, maxlen);
            strlcat(buf, buf2, maxlen);
            p += L2;
            continue;
        }
        p++;
    }
}

bool ParseAddress(LPCSTR serverstring, LPSTR addr, WORD * port, int defport)
{
    char tmp[MAX_PATH];
    strlcpy(tmp, serverstring, sizeof(tmp)-1);
    if (tmp[0] == '[') {
        // numeric IPv6,  possibly with port
        LPSTR p = strchr(tmp, ']');
        if (!p)
            return false;
        *p++ = 0;
        strcpy(addr, tmp + 1);
        *port = (*p == ':') ? atoi(p + 1) : defport;
        return true;
    }
    LPSTR p = strchr(tmp, ':');
    LPSTR t = strrchr(tmp, ':');
    if (p && p == t) {
        // hostname or numeric IPv4 with port
        *p++ = 0;
        *port = atoi(p);
    } else {
        // hostname,  numeric IPv4 or IPv6,  all without port
        *port = defport;
    }
    strcpy(addr, tmp);
    return true;
}

bool IsNumericIPv6(LPCSTR addr)
{
    LPCSTR p = strchr(addr, ':');
    LPCSTR t = strrchr(addr, ':');
    if (p && p == t)
        return false;
    return p ? true : false;
}

__forceinline
static size_t countdots(LPCWSTR buf)
{
    size_t retval = 0;
    while (*buf) {
        if (*buf == '.')
            retval++;
        buf++;
    }
    return retval;
}

static bool filematchw(LPWSTR swild, LPCWSTR slbox)
{
    WCHAR pattern[260];
    WCHAR buffer[260];

    wcscpy(pattern, swild);
    _wcsupr(pattern);
    wcscpy(buffer, slbox);
    _wcsupr(buffer);

    LPWSTR ppat = pattern;
    LPWSTR pbuf = buffer;
    LPWSTR pendbuf = pbuf + wcslen(pbuf);
    LPWSTR PosOfStar = pbuf;
    bool retval = false;
    bool failed = false;
    while (!retval && !failed) {
        if (ppat[0] == 0 && pbuf[0] == 0) {
            retval = true;   /* FIXME: return true? */
            continue;
        }
        if (ppat[0] == '*') {   // just skip to next
            PosOfStar = pbuf;
            ppat++;
            if (!ppat[0])
                retval = true;    // * am Schluss bedeutet full Match!   /* FIXME: return true? */
            continue;
        }
        if ((ppat[0] == '?' && pbuf[0]) || ppat[0] == pbuf[0]) {   // Match!
            ppat++;
            pbuf++;
            continue;
        }
        if (!pbuf[0] && ppat[0] == '.') {
            if (ppat[1] == '*' && !ppat[2]) {
                retval = true;  // xyz.* matches also xyz
                continue;  /* FIXME: return true? */
            }
            if (!ppat[1]) {
                // Spezialfall: '.' am Ende bedeutet,  dass buffer und pattern gleich viele '.' enthalten sollen!
                ppat[0] = 0;  // last pattern-dot doesn't count!
                retval = countdots(buffer) == countdots(pattern);
                failed = !retval;
                continue;
            }
        }
        // Backtrack!
        while (ppat > pattern && ppat[0] != '*') ppat--;
        if (ppat[0] != '*') {
            failed = true;
            continue;  /* FIXME: return retval? */
        }
        ppat++;
        PosOfStar++;
        pbuf = PosOfStar;
        if (PosOfStar > pendbuf)
            failed = true;    /* FIXME: return retval? */
    }
    return retval;
}

LPWSTR wcstok2_p0 = NULL;

LPWSTR wcstok2(LPWSTR name)
{
    if (name)
        wcstok2_p0 = name;
    if (!wcstok2_p0)
        return wcstok2_p0;
    LPWSTR p1 = wcschr(wcstok2_p0, '"');
    LPWSTR p2 = wcschr(wcstok2_p0, ' ');
    LPWSTR p3 = wcschr(wcstok2_p0, ';');
    if (p3 && (!p2 || p2 > p3))
        p2 = p3;
    if (!p1 || (p2 && p1 > p2)) {
        LPWSTR retval = wcstok2_p0;
        wcstok2_p0 = p2;
        if (wcstok2_p0)
            *wcstok2_p0++ = 0;
        return retval;
    }
    // Anführungszeichen!
    p3 = wcschr(p1 + 1, '"');
    if (!p3) {
        p3 = p1 + wcslen(p1);
    } else {
        *p3++ = 0;
        while (*p3 == ' ') p3++;
    }
    wcstok2_p0 = p3;
    return p1 + 1;
}

bool MultiFileMatchW(LPCWSTR wild, LPCWSTR name)
{
    WCHAR sincl[1024];
    bool io = false;
    wcslcpy2(sincl, wild, _countof(sincl)-1);
    // first, check for | symbol, all behind it is negated!
    LPWSTR p = wcschr(sincl, '|');
    if (p) {
        if (p == sincl)
            io = true;
        *p++ = 0;
        while (*p == ' ') p++;
    }
    LPWSTR swild = wcstok2(sincl);
    // included files
    while (swild && !io) {
        if (filematchw(swild, name))
            io = true;
        swild = wcstok2(NULL);
    }
    // excluded files
    if (io && p) {
        swild = wcstok2(p);
        while (swild && io) {
            if (filematchw(swild, name))
                io = false;
            swild = wcstok2(NULL);
        }
    }
    return io;
}

