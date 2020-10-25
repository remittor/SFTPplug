#include <windows.h>
#include <time.h>
#include "utils.h"

LPTSTR strcatbackslash(LPTSTR thedir)
{
    if (thedir[0])
        if (thedir[strlen(thedir)-1] != '\\')
            strcat(thedir,  "\\");
    return thedir;
}

LPTSTR strlcatforwardslash(LPTSTR thedir, int maxlen)
{
    if (thedir[0])
        if (thedir[strlen(thedir)-1] != '/')
            strlcat(thedir, "/", maxlen);
    return thedir;
}

char* strlcatbackslash(char* thedir, int maxlen)
{
    if (thedir[0] && strlen(thedir) < (size_t)maxlen)
        if (thedir[strlen(thedir)-1] != '\\')
            strlcat(thedir, "\\", maxlen);
    return thedir;
}

WCHAR* wcslcatbackslash(WCHAR* thedir, int maxlen)
{
    if (thedir[0] && wcslen(thedir) < (size_t)maxlen)
        if (thedir[wcslen(thedir)-1] != '\\')
            wcsncat(thedir, L"\\", maxlen);
    return thedir;
}

void cutlastbackslash(char* thedir)
{
    int l = strlen(thedir);
    if (l && thedir[l-1] == '\\')
        thedir[l-1] = 0;
}

char* strlcpy(char* p, const char* p2, int maxlen)
{
    if ((int)strlen(p2) >= maxlen) {
        strncpy(p, p2, maxlen);
        p[maxlen] = 0;
    } else {
        strcpy(p, p2);
    }
    return p;
}

WCHAR* wcslcpy2(WCHAR* p, const WCHAR* p2, int maxlen)
{
    if ((int)wcslen(p2) >= maxlen) {
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
char* strlcat(char* p, const char* p2, int maxlen)
{
    return strncat(p, p2, maxlen - strlen(p));
}

char* ReplaceBackslashBySlash(char* thedir)
{
    char* p;
    p = thedir;
    while (p[0]) {
        if (p[0] == '\\')
            p[0] = '/';
        p++;
    }
    return thedir;
}

WCHAR* ReplaceBackslashBySlashW(WCHAR* thedir)
{
    WCHAR* p;
    p = thedir;
    while (p[0]) {
        if (p[0] == '\\')
            p[0] = '/';
        p++;
    }
    return thedir;
}

char* ReplaceSlashByBackslash(char* thedir)
{
    char* p;
    p = thedir;
    while (p[0]) {
        if (p[0] == '/')
            p[0] = '\\';
        p++;
    }
    return thedir;
}

WCHAR* ReplaceSlashByBackslashW(WCHAR* thedir)
{
    WCHAR* p;
    p = thedir;
    while (p[0]) {
        if (p[0] == '/')
            p[0] = '\\';
        p++;
    }
    return thedir;
}

int conv2bytes(char* p)
{
    char buf[16];
    strlcpy(buf, p, 2);
    return atoi(buf);
}

BOOL ConvertIsoDateToDateTime(char* pdatetimefield, FILETIME *ft)
{
    SYSTEMTIME st;
    FILETIME ft2;
    char buf[16];
    strlcpy(buf, pdatetimefield, 4);
    st.wYear = atoi(buf);
    st.wMonth = conv2bytes(pdatetimefield+4);
    st.wDay = conv2bytes(pdatetimefield+6);
    st.wHour = conv2bytes(pdatetimefield+8);
    st.wMinute = conv2bytes(pdatetimefield+10);
    st.wSecond = conv2bytes(pdatetimefield+12);
    st.wDayOfWeek = 0;
    st.wMilliseconds = 0;
    if (!SystemTimeToFileTime(&st, &ft2)) {
        ft->dwHighDateTime = 0xFFFFFFFF;
        ft->dwLowDateTime  = 0xFFFFFFFE;
        return false;
    } else {
        return LocalFileTimeToFileTime(&ft2, ft);  // Totalcmd expects system time!
    }
}

BOOL UnixTimeToLocalTime(time_t* mtime, LPFILETIME ft)
{
    struct tm* fttm=gmtime(mtime);
    SYSTEMTIME st;
    FILETIME ft2;

    st.wYear = fttm->tm_year;
    if (st.wYear < 200)
        st.wYear += 1900;
    st.wMonth = fttm->tm_mon + 1;  // 0-11 in struct tm*
    st.wDay = fttm->tm_mday;
    st.wHour = fttm->tm_hour;
    st.wMinute = fttm->tm_min;
    st.wSecond = fttm->tm_sec;
    st.wDayOfWeek = 0;
    st.wMilliseconds = 0;
    if (SystemTimeToFileTime(&st, &ft2)) {
        return LocalFileTimeToFileTime(&ft2, ft);  // Wincmd expects system time!
    }
    return false;
}

void Conv2Chars(char* buf, int nr)
{
    if (nr <= 9) {
        buf[0] = '0';
        buf[1] = '0' + nr;
    } else {
        itoa(nr, buf, 10);
    }
}

BOOL CreateIsoDateString(FILETIME *ft, char* buf)
{
    SYSTEMTIME datetime;
    FILETIME ft2;
    buf[0] = 0;
    FileTimeToLocalFileTime(ft, &ft2);  // Totalcmd expects system time!
    if (FileTimeToSystemTime(&ft2, &datetime)) {
        itoa(datetime.wYear, buf, 10);
        Conv2Chars(buf+4, datetime.wMonth);
        Conv2Chars(buf+6, datetime.wDay);
        Conv2Chars(buf+8, datetime.wHour);
        Conv2Chars(buf+10, datetime.wMinute);
        Conv2Chars(buf+12, datetime.wSecond);
        buf[14] = 0;
        return true;
    }
    return false;
}

static const WORD crctable_palm[256] = {
    0x0000,  0x1021,  0x2042,  0x3063,  0x4084,  0x50A5,  0x60C6,  0x70E7, 
    0x8108,  0x9129,  0xA14A,  0xB16B,  0xC18C,  0xD1AD,  0xE1CE,  0xF1EF, 
    0x1231,  0x0210,  0x3273,  0x2252,  0x52B5,  0x4294,  0x72F7,  0x62D6, 
    0x9339,  0x8318,  0xB37B,  0xA35A,  0xD3BD,  0xC39C,  0xF3FF,  0xE3DE, 
    0x2462,  0x3443,  0x0420,  0x1401,  0x64E6,  0x74C7,  0x44A4,  0x5485, 
    0xA56A,  0xB54B,  0x8528,  0x9509,  0xE5EE,  0xF5CF,  0xC5AC,  0xD58D, 
    0x3653,  0x2672,  0x1611,  0x0630,  0x76D7,  0x66F6,  0x5695,  0x46B4, 
    0xB75B,  0xA77A,  0x9719,  0x8738,  0xF7DF,  0xE7FE,  0xD79D,  0xC7BC, 
    0x48C4,  0x58E5,  0x6886,  0x78A7,  0x0840,  0x1861,  0x2802,  0x3823, 
    0xC9CC,  0xD9ED,  0xE98E,  0xF9AF,  0x8948,  0x9969,  0xA90A,  0xB92B, 
    0x5AF5,  0x4AD4,  0x7AB7,  0x6A96,  0x1A71,  0x0A50,  0x3A33,  0x2A12, 
    0xDBFD,  0xCBDC,  0xFBBF,  0xEB9E,  0x9B79,  0x8B58,  0xBB3B,  0xAB1A, 
    0x6CA6,  0x7C87,  0x4CE4,  0x5CC5,  0x2C22,  0x3C03,  0x0C60,  0x1C41, 
    0xEDAE,  0xFD8F,  0xCDEC,  0xDDCD,  0xAD2A,  0xBD0B,  0x8D68,  0x9D49, 
    0x7E97,  0x6EB6,  0x5ED5,  0x4EF4,  0x3E13,  0x2E32,  0x1E51,  0x0E70, 
    0xFF9F,  0xEFBE,  0xDFDD,  0xCFFC,  0xBF1B,  0xAF3A,  0x9F59,  0x8F78, 
    0x9188,  0x81A9,  0xB1CA,  0xA1EB,  0xD10C,  0xC12D,  0xF14E,  0xE16F, 
    0x1080,  0x00A1,  0x30C2,  0x20E3,  0x5004,  0x4025,  0x7046,  0x6067, 
    0x83B9,  0x9398,  0xA3FB,  0xB3DA,  0xC33D,  0xD31C,  0xE37F,  0xF35E, 
    0x02B1,  0x1290,  0x22F3,  0x32D2,  0x4235,  0x5214,  0x6277,  0x7256, 
    0xB5EA,  0xA5CB,  0x95A8,  0x8589,  0xF56E,  0xE54F,  0xD52C,  0xC50D, 
    0x34E2,  0x24C3,  0x14A0,  0x0481,  0x7466,  0x6447,  0x5424,  0x4405, 
    0xA7DB,  0xB7FA,  0x8799,  0x97B8,  0xE75F,  0xF77E,  0xC71D,  0xD73C, 
    0x26D3,  0x36F2,  0x0691,  0x16B0,  0x6657,  0x7676,  0x4615,  0x5634, 
    0xD94C,  0xC96D,  0xF90E,  0xE92F,  0x99C8,  0x89E9,  0xB98A,  0xA9AB, 
    0x5844,  0x4865,  0x7806,  0x6827,  0x18C0,  0x08E1,  0x3882,  0x28A3, 
    0xCB7D,  0xDB5C,  0xEB3F,  0xFB1E,  0x8BF9,  0x9BD8,  0xABBB,  0xBB9A, 
    0x4A75,  0x5A54,  0x6A37,  0x7A16,  0x0AF1,  0x1AD0,  0x2AB3,  0x3A92, 
    0xFD2E,  0xED0F,  0xDD6C,  0xCD4D,  0xBDAA,  0xAD8B,  0x9DE8,  0x8DC9, 
    0x7C26,  0x6C07,  0x5C64,  0x4C45,  0x3CA2,  0x2C83,  0x1CE0,  0x0CC1, 
    0xEF1F,  0xFF3E,  0xCF5D,  0xDF7C,  0xAF9B,  0xBFBA,  0x8FD9,  0x9FF8, 
    0x6E17,  0x7E36,  0x4E55,  0x5E74,  0x2E93,  0x3EB2,  0x0ED1,  0x1EF0
};


WORD Crc16CalcBlock(char* p,  int len,  WORD crc16)
{
    while (len > 0) {
        crc16 = (crc16 << 8) ^ crctable_palm[ (unsigned char)((crc16 >> 8) ^ (unsigned char)*p++) ];
        len--;
    }
    return crc16;
}

char MimeTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


char EncodeMIME(unsigned char ch)
{
    return MimeTable[ch & 0x3F];
}

void EncodeMimeTriple(char* inbuf, int j, char* outbuf)
{
    unsigned char c1, c2, c3, c4;
    outbuf[4] = 0;
    c1 = (unsigned char)(inbuf[0]) >> 2;
    c2 = (((unsigned char)(inbuf[0]) << 4) & 0x30) | (((unsigned char)(inbuf[1]) >> 4) & 0xF);
    c3 = (((unsigned char)(inbuf[1]) << 2) & 0x3C) | (((unsigned char)(inbuf[2]) >> 6) & 0x3);
    c4 = ((unsigned char)(inbuf[2]) & 0x3F);
    outbuf[0] = EncodeMIME(c1);
    outbuf[1] = EncodeMIME(c2);
    if (j > 1)
        outbuf[2] = EncodeMIME(c3);
    else
        outbuf[2] = '=';          //Last char padding
    if (j > 2)
        outbuf[3] = EncodeMIME(c4);
    else
        outbuf[3] = '=';
}

void MimeEncode(char* inputstr, char* outputstr, int maxlen)
{
    char bufin[8];
    char buf[8];
    int i, j, readbytes;
    outputstr[0] = 0;
    j = strlen(inputstr);
    readbytes = j;
    i = 0;
    while (i < readbytes) {
        memset(bufin, 0, 4);
        strlcpy(bufin, inputstr + i, 3);
        EncodeMimeTriple(bufin, j, buf);
        strlcat(outputstr, buf, maxlen);
        i += 3;
        j -= 3;
    }
}

static const short base64_reverse_table[256] = {
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

int MimeDecode(char* inputstr, int srclen, char* outputstr, int maxlen)
{
    unsigned char *s, *d;
    short v;
    int i = 0, len = 0;
    d = (unsigned char *) outputstr;

    for (s = (unsigned char *) inputstr; (char *)s < (inputstr + srclen); s++) {
        v = base64_reverse_table[*s];
        if (v < 0)
            continue;
        switch (i % 4) {
        case 0:
            d[len] = (unsigned char)(v << 2);
            break;
        case 1:
            d[len++] |= v >> 4;
            d[len] = (unsigned char)(v << 4);
            break;
        case 2:
            d[len++] |= v >> 2;
            d[len] = (unsigned char)(v << 6);
            break;
        case 3:
            d[len++] |= v;
            break;
        }
        i++;
        if (len >= maxlen - 1)
            break;
    }
    return len;
}


void ReplaceEnvVars(char* buf, int buflen) //Replace %name% by environment variable
{
    char buf2[1024];
    char envname[MAX_PATH], envbuf[MAX_PATH];
    char *p, *p1, *p2;
    do {
        p = strchr(buf, '%');
        if (p) {
            p1 = strchr(p + 1, '%');
            if (p1 == p + 1)
                p1 = NULL;   //found %%
        } else
            p1 = NULL;
        if (p1) {
            p1[0] = 0;
            strcpy(envname, p + 1);
            p1[0] = '%';
            if (GetEnvironmentVariable(envname, envbuf, MAX_PATH-1))
                p2 = envbuf;
            else
                p2 = NULL;
            if (p2) {
                p[0] = 0;
                strlcpy(buf2, buf, sizeof(buf2)-1);
                strlcat(buf2, p2, sizeof(buf2)-1);
                strlcat(buf2, p1+1, sizeof(buf2)-1);
                strlcpy(buf, buf2, buflen);
            }
        } else
            p1 = NULL;    // Stop loop
    } while (p1);
}

void ReplaceSubString(char* buf, const char* fromstr, const char* tostr, int maxlen)
{
    char buf2[1024];
    char* p;
    int L = strlen(fromstr);
    int L2 = strlen(tostr);
    if (L == 0)  // nothing to do
        return;
    p = buf;
    while (p[0]) {
        if (p[0] == fromstr[0] && strncmp(p, fromstr, L) == 0) {
            p[0] = 0;
            strlcpy(buf2, p + L, sizeof(buf2)-1);    // save rest of string
            strlcat(buf, tostr, maxlen);
            strlcat(buf, buf2, maxlen);
        p += L2;
    } else
        p++;
    }
}

BOOL ParseAddress(char* serverstring, char* addr, unsigned short* port, int defport)
{
    char tmp[MAX_PATH];
    char *p, *t;

    strlcpy(tmp, serverstring, MAX_PATH-1);
    if (tmp[0] == '[') {
        // numeric IPv6,  possibly with port
        p = strchr(tmp, ']');
        if (p) {
            p[0] = 0;
            strcpy(addr, tmp+1);
            if (p[1] == ':') {
                p += 2;
                *port = atoi(p);
            } else
                *port = defport;
            return TRUE;
        } else
            return FALSE;
    } else {
        p = strchr(tmp, ':');
        t = strrchr(tmp, ':');
        if (p && p == t) {
            // hostname or numeric IPv4 with port
            p[0] = 0;
            p++;
            *port = atoi(p);
        } else {
            // hostname,  numeric IPv4 or IPv6,  all without port
            *port = defport;
        }
        strcpy(addr, tmp);
        return TRUE;
    }
}

BOOL IsNumericIPv6(char* addr)
{
    char *p = strchr(addr, ':');
    char *t = strrchr(addr, ':');
    if (p && p == t) 
        return FALSE;
    else
        return (p != NULL);
}

int countdots(WCHAR* buf)
{
    WCHAR* p;
    int retval;

    p = buf;
    retval = 0;
    while (p[0]) {
        if (p[0] == '.')
            retval++;
        p++;
    }
    return retval;
}

bool filematchw(WCHAR* swild, WCHAR* slbox)
{
    WCHAR pattern[260], buffer[260];
    WCHAR* ppat, *pbuf, *pendbuf, *PosOfStar;
    bool failed, retval;

    wcscpy(pattern, swild);
    _wcsupr(pattern);
    wcscpy(buffer, slbox);
    _wcsupr(buffer);
    retval = false;
    failed = false;
    ppat = pattern;
    pbuf = buffer;
    pendbuf = pbuf + wcslen(pbuf);
    PosOfStar = pbuf;
    do {
        if (ppat[0] == 0 && pbuf[0] == 0)
            retval = true;
        else if (ppat[0] == '*') {   // just skip to next
            PosOfStar = pbuf;
            ppat++;
            if (!ppat[0])
                retval = true;    // * am Schluss bedeutet full Match!
        } else {
            if ((ppat[0] == '?' && pbuf[0]) || ppat[0] == pbuf[0]) {   // Match!
                ppat++;
                pbuf++;
            } else if (!pbuf[0] && ppat[0] == '.' && ppat[1] == '*' && !ppat[2])
                retval = true;  // xyz.* matches also xyz
            else if (!pbuf[0] && ppat[0] == '.' && !ppat[1]) {
                // Spezialfall: '.' am Ende bedeutet,  dass buffer und pattern gleich viele '.' enthalten sollen!
                ppat[0] = 0;  // last pattern-dot doesn't count!
                retval = countdots(buffer) == countdots(pattern);
                failed = !retval;
            } else {  // Backtrack!
                while (ppat > pattern && ppat[0] != '*')
                    ppat--;
                if (ppat[0] == '*') {
                    ppat++;
                    PosOfStar++;
                    if (PosOfStar > pendbuf)
                        failed = true;
                    pbuf = PosOfStar;
                } else
                    failed=true;
            }
        }
    } while (!retval && !failed);
    return retval;
}

WCHAR* wcstok2_p0;

WCHAR* wcstok2(WCHAR* name)
{
    WCHAR *p1, *p2, *p3, *retval;
    if (name) wcstok2_p0 = name;
    if (!wcstok2_p0)
        return wcstok2_p0;
    p1 = wcschr(wcstok2_p0, '"');
    p2 = wcschr(wcstok2_p0, ' ');
    p3 = wcschr(wcstok2_p0, ';');
    if (p3)
        if (!p2)
            p2 = p3;
        else if ((DWORD)(p2) > (DWORD)(p3))
            p2=p3;
    if (!p1 || (p2 && (DWORD)(p1) > (DWORD)(p2))) {
        retval = wcstok2_p0;
        wcstok2_p0 = p2;
        if (wcstok2_p0) {
            wcstok2_p0[0] = 0;
            wcstok2_p0++;
        }
    } else {      // Anführungszeichen!
        p3 = wcschr(p1+1, '"');
        if (!p3)
            p3 = p1 + wcslen(p1);
        else {
            p3[0] = 0;
            p3++;
            while (p3[0] == ' ')
                p3++;
        }
        retval = p1 + 1;
        wcstok2_p0 = p3;
    }
    return retval;
}

bool MultiFileMatchW(WCHAR* wild, WCHAR* name)
{
    WCHAR sincl[1024];
    WCHAR *swild, *p;
    bool io;

    io = false;
    wcslcpy2(sincl, wild, countof(sincl)-1);
    // first,  check for | symbol,  all behind it is negated!
    p = wcschr(sincl, '|');
    if (p) {
        p[0] = 0;
        if (p == sincl)
            io = true;
        p++;
        while (p[0] == ' ')
            p++;
    }
    swild = wcstok2(sincl);
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

