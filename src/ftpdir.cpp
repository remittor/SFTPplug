#include <windows.h>
#include "utils.h"
#include "ftpdir.h"

LPCWSTR month[37] = { L"",
    L"JAN", L"FEB", L"MAR", L"APR", L"MAY", L"JUN", L"JUL", L"AUG", L"SEP", L"OCT", L"NOV", L"DEC", 
    L"",    L"",    L"MÄR", L"",    L"MAI", L"",    L"",    L"",    L"",    L"OKT", L"",    L"DEZ", 
    L"",    L"FEV", L"MRZ", L"AVR", L"",    L"JUI", L"",    L"",    L"",    L"",    L"",    L""
};

__forceinline
static bool LineContainsonlySlashes(LPCWSTR lpStr)
{
    while (lpStr[0] == L' ' || lpStr[0] == L'-') lpStr++;
    return lpStr[0] == 0;
}

__forceinline
static WCHAR upcase(WCHAR ch)
{
    return (size_t)CharUpperW((LPWSTR)ch) & 0xFFFF;
}

__forceinline
static bool isadigit(WCHAR ch)
{
    return (ch >= L'0' && ch <= L'9');
}

__forceinline
static size_t _cutDigitsW(LPCWSTR instr, LPWSTR outstr, size_t outstrcap)
{
    outstr[0] = 0;
    if (instr[0] == 0)
        return 0;
    size_t len = 0;
    while (isadigit(instr[len]) && len < outstrcap - 1) {
        outstr[len] = instr[len];
        len++;
    }
    if (len == 0)
        return 0;
    outstr[len] = 0;
    return len;
}

static int DecodeNumber64W(LPCWSTR s, INT64 * number)
{
    WCHAR buf[32];
    size_t len = _cutDigitsW(s, buf, sizeof(buf));
    if (len == 0)
        return 0;
    if (!StrToInt64ExW(buf, STIF_DEFAULT, number))
        return -1;
    return len;
}

static int DecodeNumber32W(LPCWSTR s, int * number)
{
    WCHAR buf[12];
    size_t len = _cutDigitsW(s, buf, sizeof(buf));
    if (len == 0)
        return 0;
    if (len > 10)
        return 0;   /* 64-bit not supported!!! */
    buf[len] = 0;
    *number = _wtoi(buf);  /* FIXME: replace to StrToInt64ExW for check errors */
    return len;
}

static bool DecodeNumber(LPWSTR * s, int * number)
{
    size_t len = DecodeNumber32W(*s, number);
    if (len <= 0)
        return false;
    const WCHAR ch = *s[len];
    if (ch && upcase(ch) >= L'A' && upcase(ch) <= L'Z')  /* FIXME: upcase not needed */
        return false;
    *s += len + 1;
    return true;
}

__forceinline
static int get2digits(LPCWSTR str)
{
    union {
        WCHAR buf[4];
        UINT64 ui64;
    } a;
    a.ui64 = *(PUINT32)str;
    return _wtoi(a.buf);
}

__forceinline
static int get4digits(LPCWSTR str)
{
    union {
        WCHAR buf[8];
        struct {
            UINT64 ui64;
            SIZE_T zero;
        } s;
    } a;
    a.s.ui64 = *(PUINT64)str;
    a.s.zero = 0;
    return _wtoi(a.buf);
}

static const WCHAR szTrim[] = L" \r\n\t";

static bool check(LPCWSTR s1, PDWORD UnixAttr) // Check if s1=Permissions!
{
    static const char s2[] = "RWXRWXRWX";
    *UnixAttr = 0;
    for (size_t i = 0; i <= 8; i++) {
        if (s1[i] == '-')
            continue;
        const WCHAR s1uc = upcase(s1[i]);
        if (s1uc == s2[i]) {
            *UnixAttr |= (1 << (8 - i));
            continue;
        }
        if (s2[i] == 'X' && !wcschr(L"LST", s1uc)) {
            *UnixAttr = 0;
            return false;
        }
        if (s1[i] == 's' || s1[i] == 't')
            *UnixAttr |= (1 << (8 - i));
    }
    return true;
}

/*USR Site:
-[R----F-]  1 emandera   217369 Jan 31 09:36 usr.qif
-[R----F-]  1 emandera      666 Nov 09 09:21 usr.adf
d[R----F-]  1 supervis      512 Mar 17 09:45 dl24
d[R----F-]  1 supervis      512 Mar 17 09:45 dl17
*/
static bool NovellUnix(LPCWSTR s1)
{
    while (*s1 == ' ') s1++;
    if (*s1 != '[')
        return false;
    LPCWSTR p = wcschr(s1, ']');
    if (!p || p - s1 < 6)
        return false;
    for (s1++; s1 < p; s1++) {
        if (*s1 == ' ')
            return false;
    }
    return true;
}

static LPCWSTR FindUnixPermissions(LPCWSTR lpStr, PDWORD UnixAttr)
{
    if (LineContainsonlySlashes(lpStr))
        return NULL;
    *UnixAttr = 0;
    size_t imax = wcslen(lpStr);
    if (imax < 10)
        return NULL;
    imax -= 10;
    if (imax > 10)
        imax = 10;       // Don't confuse file name with permissions!
    for (size_t i = 0; i <= imax; i++) {
        const WCHAR ch = upcase(lpStr[i]);
        if (wcschr(L"-DLFBCP|", ch)) {
            if (check(lpStr + i + 1, UnixAttr) || NovellUnix(lpStr + i + 1)) {
                if (ch == 'L')
                    (*UnixAttr) |= 0xA000;
                return lpStr + i;
            }
        }
    }
    return NULL;
}

/* strip trailing garbage from the line if there is any. */
__forceinline
static size_t StripTrailingGarbage(LPWSTR szLine)
{
    size_t nIndex = wcslen(szLine);
    while (nIndex > 2 && wcschr(szTrim, szLine[nIndex-1])) {
        szLine[nIndex] = 0;
        nIndex--;
    }
    return nIndex;
}

static LPWSTR FindName(LPWSTR szLine)
{
    size_t nIndex = StripTrailingGarbage(szLine);

    /* now the name SHOULD be the last thing on the line */
    LPWSTR pStr = wcsrchr(szLine, ' ');
    pStr = (pStr == NULL) ? szLine : pStr + 1;

    /*Suche nach -> */
    if (pStr > szLine + 2) {
        LPWSTR p = pStr;
        p--;
        while (p[0] == ' ') p--;
        if (p != szLine)
            p--;
        if (p[0] == '-' && p[1] == '>' && p != szLine) {  /* Verweis! */
            p--;
            while (p[0] == ' ') p--;
            p[1] = 0;
            pStr = wcsrchr(szLine, ' ');
            pStr = (pStr == NULL) ? szLine : pStr + 1;
        }
    }
    return pStr;
}

/* Search with Date instead of last string */
/* name may contain spaces on MAC ftpd! */
static LPWSTR FindNameUnix(LPWSTR szLine, int * link, int flags)
{
    WCHAR linebuf[256];
    int num;
    bool longdatetype = (flags & FLAG_HAVE_LONGDATETYPE) ? true : false;
    
    *link = 0;        /* No link */
    StripTrailingGarbage(szLine);
    wcslcpy2(linebuf, szLine, _countof(linebuf)-1);
    CharUpperBuffW(linebuf, wcslen(linebuf));

    /* now look for the DATE! */

    LPWSTR minmonthpos = NULL;        /* Warning: file name may be a month name! */

    for (size_t i = 1; i <= 36; i++) {
        if (month[i][0] == 0)
            continue;
        /* Englisch und deutsch! */
        LPWSTR p = linebuf;
        while (1) {
            LPWSTR monthpos = wcsstr(p, month[i]);
            if (monthpos == NULL)
                break;
            if (monthpos != p) {
                size_t incr = 3;
                if (wcschr(L" \t-, ", monthpos[3]) == NULL) {
                    incr = 0;
                    if (wcschr(L" \t-, /, ", monthpos[4]) != NULL) {
                        incr = 4;
                    }
                }
                if (incr == 0)
                    break;
                monthpos -= 2;
                if (wcschr(L" \t-, /", monthpos[1]) == NULL)
                    break;
                bool daybeforemonth = (monthpos[0] == '.');
                monthpos += 2;
                monthpos += incr;
                for (size_t j = 1; j <= 3; j++) {      /* Max 3 Leerzeichen! */
                    if (wcschr(L" \t-, /", monthpos[0]) != NULL)
                        monthpos++;
                }
                if (!isadigit(monthpos[0]))
                    break;
                if (!daybeforemonth) {
                    if (!DecodeNumber(&monthpos, &num))  /* Tag überspringen */
                        break;
                    while (monthpos[0]==' ') monthpos++;
                }
                if (minmonthpos == NULL || monthpos < minmonthpos)
                    minmonthpos = monthpos;
            }
            p = monthpos + 1;
        }
    }
    /* Minmonthpos zeigt nun auf Jahr bzw. Zeit */
    if (minmonthpos != NULL) {
        LPWSTR p = szLine + (minmonthpos - linebuf); /* Auf szLine zeigen!!! */
        if (!DecodeNumber(&p, &num))    /* Stunde bzw. Jahr überspringen */
            goto fin;

        LPWSTR px = p;
        const WCHAR ch = p[-1];
        if (ch == ':' || (ch == '.' && isadigit(p[0]))) {
            if (!DecodeNumber(&p, &num))  /* Zeit */
                goto fin;

            px = longdatetype ? p + 8 : p;
        } else {                            /* Jahr */
            px = p;                         /* Novell: Zeit nach Jahr,  oft mit am/pm! */
            while (p[0] == ' ') p++;
            if (wcslen(p) <= 5)
                goto next;

            if (!DecodeNumber(&p, &num))    /* Stunde überspringen */
                goto next;

            const WCHAR ch = p[-1];                    /* Achtung: nicht Namen als Zahl erkennen! */
            if (num <= 24 && num >= 0 && (ch == ':' || (ch == '.' && isadigit(p[0])))) {  /* Zeit */
                if (!DecodeNumber(&p, &num))
                    goto next;

                const WCHAR ch = p[-1];                /* Achtung: nicht Namen als Zahl erkennen! */
                if ((ch == ' ' || ch == 9) && (num < 60) && (num >= 0)) {
                    /* Look for am/pm */
                    if (p[1] == 'm' && p[2] == ' ' && (p[0] == 'a' || p[0] == 'p'))
                        p += 2;
                    px = p;
                }
            }
        }
next:
        p = px;
        while (p[0] == ' ') p++;
        px = p;
        p = wcsstr(p, L" ->");
        if (p != NULL) {
            LPWSTR p2 = wcsrchr(p, '/');
            if (p2 == NULL)
                p2 = p;
            LPWSTR p1 = wcschr(p2, '.');
            if (p1 != NULL && p1[1] == '.')
                p1 = wcschr(p1 + 2, '.');  /* check for ../name */
            if (p1)
                *link = 1;        /* probably a file */
            else
                *link = 2;        /* probably a dir */
            p[0] = 0;  /* Link !*/
        }
        return px;
    }
fin:
    return FindName(szLine);  /* Do it the 'normal' way */
}

static INT64 GetSizeFromFront(LPCWSTR lpstr)
{
    LPCWSTR pstr = lpstr;
    while (*pstr && *pstr != ' ') pstr++;                // Permissions
    while (*pstr == ' ') pstr++;                         // Abstand
    if (isadigit(*pstr)) {
        while (*pstr && *pstr != ' ') pstr++;            // Zahl
        while (*pstr == ' ') pstr++;                     // Abstand
    }
    while (*pstr && *pstr != ' ') pstr++;                // Owner
    while (*pstr == ' ') *pstr++;                        // Abstand
    while (*pstr && *pstr != ' ') pstr++;                // Group
    while (*pstr == ' ') *pstr++;                        // Abstand
    if (isadigit(*pstr)) {                               // Groesse gefunden!
        INT64 result;
        int len = DecodeNumber64W(pstr, &result);
        if (len > 0)
            return result;
    }
    return -1;
}

static void ReadDateTimeSizeUnix(LPWSTR lpS, LPFILETIME datetime, PINT64 sizefile)
{
    WCHAR buf[512];
    SYSTEMTIME t = {0};
    int num;

    SetInt64ToFileTime(datetime, -1);
    *sizefile = -1;

    wcslcpy2(buf, lpS, _countof(buf)-1);
    CharUpperBuffW(buf, wcslen(buf));
    LPWSTR lpstr = buf;

    t.wMonth = 0;
    LPWSTR monthpos = NULL;

    for (size_t i = 1; i <= 36; i++) {
        if (month[i][0] == 0)
            continue;
        size_t incr = 0;
        LPWSTR p = lpstr; 
        while (1) {
            monthpos = wcsstr(p, month[i]);
            if (monthpos == NULL)
                break;   /* FIXME: may be `incr` set to 0 ??? */
            incr = 3;
            if (monthpos != lpstr) {  /* FIXME: may be (monthpos == p) ??? */
                if (wcschr(L" \t-, /", monthpos[3]) == NULL) {
                    incr = 0;
                    /* Deutsch kann auch sein 'Juni' 'März,' etc. */
                    /* -r-sr-xr-x     1 lp            bin                    16384 27. Juni 1997 enable
                       lr-xr-xr-t     1 root          sys                    20 16. März,  15:20 endif -> /opt/ansic/bin/endif*/
                    if (wcschr(L" \t-, /", monthpos[4]) != NULL) {
                        incr = 4;
                    }
                }
                if (incr && wcschr(L" \t-, /", monthpos[-1]) == NULL) {
                    incr = 0;
                    break;
                }
            }
            if (!incr)
                break;
            LPWSTR lp1 = monthpos + incr;
            for (size_t j = 1; j <= 3; j++) {      /* Max 3 Leerzeichen! */
                if (wcschr(L" \t-, ./", lp1[0]) != NULL) lp1++;
            }
            if (!isadigit(lp1[0])) {
                incr = 0;
                break;
            }
            p = monthpos + 1;
        } /* while */

        if (incr) {
            t.wMonth = i;
            while (t.wMonth > 12)
                t.wMonth -= 12;
            break;
        }
    }

    if (monthpos == NULL) {
        /* Month in other language */
        *sizefile = GetSizeFromFront(lpstr);
        return;
    }

    monthpos[-1] = 0;
    LPWSTR lpsize = monthpos - 1;
    bool daybeforemonth = false;
    if (lpsize <= buf) {
        *sizefile = GetSizeFromFront(lpstr);
    } else {
        lpsize--;
        if (lpsize[0] == '.') { /* Tag VOR Monat!!! */
            daybeforemonth = true;
            lpsize[0] = 0;
            lpsize--;
            while (lpsize > lpstr && isadigit(lpsize[0]))
                lpsize--;
            if (lpsize > lpstr)
                lpsize++;
            t.wDay = _wtoi(lpsize);
            if (t.wDay > 31)
                t.wDay = 0;
            if (lpsize > lpstr + 1)
                lpsize -= 2;
            lpsize[1] = 0;
        }
        while (lpsize > lpstr && lpsize[0] == ' ') lpsize--;
        lpsize[1] = 0;
        while (lpsize > lpstr && isadigit(lpsize[0])) lpsize--;
        if (!isadigit(lpsize[0])) lpsize++;
        *sizefile = _wtoi64(lpsize);   /* FIXME: replace to StrToInt64ExW for check errors */
    }

    LPWSTR lp = wcschr(monthpos, ' ');
    if (!lp)
        return;

    while (lp[0] == ' ') lp++;
    LPWSTR lp1 = lp;
    if (!daybeforemonth) {
        while (isadigit(lp1[0])) lp1++;

        while (wcschr(L" \t-, ./", lp1[0]) != NULL) { /* lp1 zeigt nun auf Zeit bzw. Jahr */
            *lp1++ = 0;
        }
        t.wDay = _wtoi(lp);
        if (t.wDay > 31) { /* Zeit oder Jahr gefunden! -> Tag vor Monat */
            if (*sizefile >= 1 && *sizefile <= 31) {
                t.wDay = (int)*sizefile;
                lpsize--;
                while (lpsize > lpstr && lpsize[0] == ' ') lpsize--;
                lpsize[1] = 0;
                while (lpsize > lpstr && isadigit(lpsize[0])) lpsize--;
                *sizefile = _wtoi64(lpsize);
                if (!isadigit(lpsize[0]))
                    *sizefile = GetSizeFromFront(lpstr);
                lp1 = lp;
                wcscat(lp, L" ");
            } else
                t.wDay = 0;
        }
    }
    /* Jahr oder Zeit suchen */
    t.wSecond = 0;
    if (t.wDay > 0 && lp1[0]) {
        lp = wcschr(lp1, ' ');
        if (!lp)
            return;

        bool hastime = false;
        lp[0] = 0;
        LPWSTR lpyear = lp + 1;
        LPWSTR lp2 = lp;
        lp = wcschr(lp1, ':');
        if (lp) {        /* Zeit */
            lp = wcstok(lp1, L":");
            t.wHour = _wtoi(lp);
            bool longdatetype = lp[5] == ':';
            lp = wcstok(NULL, L":");
            t.wMinute = _wtoi(lp);
            if (longdatetype) {
                lp = wcstok(NULL, L":");
                t.wSecond = _wtoi(lp);
                lpyear[4] = 0;
                t.wYear = _wtoi(lpyear);
            } else
                t.wYear = 0;
            if (t.wYear == 0) {
                SYSTEMTIME st;
                GetSystemTime(&st); /* Default to this year,  or the year before! */
                /*1 year before: problematisch,  wenn Server in anderer Zeitzone!
                    -> mindestens 2 Tage Unterschied*/
                t.wYear = st.wYear;
                if (t.wMonth > st.wMonth + 1 ||
                   (t.wMonth > st.wMonth && t.wDay > 2) ||
                   (t.wMonth == st.wMonth && t.wDay > st.wDay + 2))
                    t.wYear--;
            }
        } else {
            t.wYear = _wtoi(lp1);
            if (t.wYear < 100)
                t.wYear += 1900;
            if (t.wYear < 1980)
                t.wYear += 100;
            /* Novell: Zeit nach Jahr! */
            lp1 = lp2 + 1;
            while (lp1[0] == ' ') lp1++;
            if (DecodeNumber(&lp1, &num)) {  /*Stunde überspringen*/
                t.wHour = num;
                const WCHAR ch = lp1[-1];
                if (ch == ':' || (ch == '.' && isadigit(lp1[0])) && !DecodeNumber(&lp1, &num)) { /* Zeit */
                    lp1 = NULL;
                } else {
                    t.wMinute = num;
                    if (wcsncmp(lp1, L"PM ", 3) == 0) {        /* Zeit: pm */
                        if (t.wHour != 12)
                            t.wHour += 12;
                    } else if (wcsncmp(lp1, L"AM ", 3) == 0) { /* Zeit: am */
                        if (t.wHour == 12)
                            t.wHour = 0;
                    }
                }
            } else {
                lp1 = NULL;
            }
            if (lp1 == NULL) {
                t.wHour = 0;
                t.wMinute = 0;
                hastime = false;
            }
        }
        if (t.wYear < 1980) {
            t.wYear = 1980;
            t.wDay = 1;
            t.wMonth = 1;
        }
        if (!hastime) {
            t.wHour = 0;
            t.wMinute = 0;
            t.wSecond = 0;
        }
        t.wMilliseconds = 0;
        FILETIME datetime1;   // convert to system time
        SystemTimeToFileTime(&t, &datetime1);
        LocalFileTimeToFileTime(&datetime1, datetime);
    }
}

static void ReadDateTimeSizeUser(LPWSTR lpStr, LPWSTR lpDate, LPFILETIME datetime, PINT64 sizefile)
{
    if (lpDate) {
        LPWSTR lpSize = lpDate;
        if (lpSize > lpStr) {
            lpSize--;
            while (lpSize > lpStr && lpSize[0] == ' ') lpSize--;
            lpSize[1] = 0;
            while (lpSize > lpStr && isadigit(lpSize[0])) lpSize--;
            if (!isadigit(lpSize[0])) lpSize++;
            *sizefile = _wtoi64(lpSize);
        }
        SYSTEMTIME t;
        // Date format: >>20150712_112329
        lpDate += 2;  // skip >>
        if (wcslen(lpDate) > 15 && lpDate[8] == '_') {
            t.wYear   = get4digits(lpDate);
            t.wMonth  = get2digits(lpDate + 4);
            t.wDay    = get2digits(lpDate + 6);
            t.wHour   = get2digits(lpDate + 9);
            t.wMinute = get2digits(lpDate + 11);
            t.wSecond = get2digits(lpDate + 13);
            t.wMilliseconds = 0;
            FILETIME datetime1;  //convert to system time
            SystemTimeToFileTime(&t, &datetime1);
            LocalFileTimeToFileTime(&datetime1, datetime);
        }
    }
}

bool ReadDirLineUNIX(LPWSTR lpStr, LPWSTR name, int maxlen, PINT64 sizefile, LPFILETIME datetime, PDWORD attr, PDWORD UnixAttr, int flags)
{
    LPWSTR pstr;
    int linktest;

    /* assume UNIX ls format if permissions start with 'd' its a directory */
    *attr = 0;
    *UnixAttr = 0;
    if (wcsnicmp(lpStr, L"TOTAL", 5) == 0)
        return false;

    LPCWSTR Permissions = FindUnixPermissions(lpStr, UnixAttr); // Wegen CLIX-Unix!
    if (Permissions == NULL)
        return false;

    LPWSTR pstr2 = wcsstr(lpStr, L">>");   // user-defined date format ->easier to parse
    if (pstr2) {
        pstr = wcschr(pstr2, ' ');
        if (!pstr)
            return false;
        pstr++;
        ReadDateTimeSizeUser(lpStr, pstr2, datetime, sizefile);
    } else {
        pstr = FindNameUnix(lpStr, &linktest, flags);
        if (!pstr)
            return false;
        *attr = 0;
        if (Permissions[0] == 'l') {      // könnte beides sein!
            *attr |= falink;              // Zeigt Link an
        }
    }
    if (Permissions[0] == 'd') {
        *attr |= FILE_ATTRIBUTE_DIRECTORY;
    } else if (Permissions[0] != 'f' && Permissions[0] != '-') {
        if (wcsstr(lpStr, L"<DIR>") || wcsstr(lpStr, L"<dir>"))
            *attr |= FILE_ATTRIBUTE_DIRECTORY;
    }
    wcslcpy2(name, pstr, maxlen-1);
    pstr[0] = 0;      // Namen nicht als Monatsnamen erkennen!
    if (!pstr2)
        ReadDateTimeSizeUnix(lpStr, datetime, sizefile);

    if (*attr & (falink | FILE_ATTRIBUTE_DIRECTORY))
        *sizefile = 0;    // Wegen Progress!

    return name[0] && wcscmp(name, L".");
}

