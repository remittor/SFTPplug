#include <windows.h>
#include "utils.h"
#include "ftpdir.h"

WCHAR* month[37] = { L"",
    L"JAN", L"FEB", L"MAR", L"APR", L"MAY", L"JUN", L"JUL", L"AUG", L"SEP", L"OCT", L"NOV", L"DEC", 
    L"",    L"",    L"MÄR", L"",    L"MAI", L"",    L"",    L"",    L"",    L"OKT", L"",    L"DEZ", 
    L"",    L"FEV", L"MRZ", L"AVR", L"",    L"JUI", L"",    L"",    L"",    L"",    L"",    L""
};

BOOL LineContainsonlySlashes(WCHAR* lpStr)
{
    while (lpStr[0] == ' ' || lpStr[0] == '-') lpStr++;
    return lpStr[0] == 0;
}

WCHAR upcase(WCHAR ch)
{
    WCHAR buf[4];
    buf[0] = ch;
    buf[1] = 0;
    buf[2] = 0;
    buf[3] = 0;
    CharUpperW(buf);
    return (WCHAR)buf[0];
}

BOOL isadigit(WCHAR ch)
{
    return (ch >= '0' && ch <= '9');
}

BOOL DecodeNumber(WCHAR** s, int* number)
{
    WCHAR* s1;
    WCHAR ch;
    s1 = *s;
    while (isadigit(s1[0])) s1++;
    if (s1 != *s && !(upcase(s1[0]) >= 'A' && upcase(s1[0]) <= 'Z')) {
        ch = s1[0];
        s1[0] = 0;
        if (*s[0]) {
            *number = _wtoi(*s);
        } else {
            s1[0] = ch;
            return false;
        }
        s1[0] = ch;
        *s = s1 + 1;
        return true;
    }
    return false;
}

int get2digits(WCHAR* s)
{
    WCHAR buf[4];
    wcslcpy2(buf, s, 2);
    return _wtoi(buf);
}

int get4digits(WCHAR* s)
{
    WCHAR buf[8];
    wcslcpy2(buf, s, 4);
    return _wtoi(buf);
}

#define s2 "RWXRWXRWX"
#define szTrim L" \r\n\t"

BOOL check(WCHAR* s1, DWORD* UnixAttr) //Check if s1=Permissions!
{
    int i;
    BOOL found;

    found = true;
    *UnixAttr = 0;
    for (i = 0; i <= 8; i++) {
        if (s1[i] != '-') {
            if (upcase(s1[i]) == s2[i])
                *UnixAttr |= (1 << (8 - i));
            else {
                if ((s2[i] == 'X') == (wcschr(L"LST", upcase(s1[i])) == NULL)) {
                    *UnixAttr = 0;
                    found = false;
                    break;
                } else
                    if (s1[i] == 's' || s1[i] == 't')
                        *UnixAttr |= (1 << (8 - i));
            }
        }
    }
    return found;
}

/*USR Site:
-[R----F-]  1 emandera   217369 Jan 31 09:36 usr.qif
-[R----F-]  1 emandera      666 Nov 09 09:21 usr.adf
d[R----F-]  1 supervis      512 Mar 17 09:45 dl24
d[R----F-]  1 supervis      512 Mar 17 09:45 dl17
*/
BOOL NovellUnix(WCHAR* s1)
{
    int i;
    WCHAR* p;
    while (s1[0] == ' ') s1++;
    BOOL result = (s1[0] == '[');
    if (result) {
        p = wcschr(s1, ']');
        if (p == NULL || p - s1 < 6)
            result = false;
        else {
            for (i = 1; i <= p - s1; i++)
                if (s1[i] == ' ')
                    result = false;
        }
    }
    return result;
}

WCHAR* FindUnixPermissions(WCHAR* lpStr, DWORD* UnixAttr)
{
    int i, imax;
    WCHAR ch;

    if (LineContainsonlySlashes(lpStr))
        return NULL;
    *UnixAttr = 0;
    imax = wcslen(lpStr) - 10;
    if (imax > 10) imax = 10;       //Don't confuse file name with permissions!
    for (i = 0; i <= imax; i++) {
        ch = upcase(lpStr[i]);
        if (wcschr(L"-DLFBCP|", ch)) {
            if (check(lpStr + i + 1, UnixAttr) || NovellUnix(lpStr + i + 1)) {
                return lpStr + i;
            }
        }
    }
    return NULL;
}

WCHAR* FindName(WCHAR* szLine)
{
    int nIndex;
    WCHAR *pStr, *p;

    nIndex = wcslen(szLine);

    /* strip trailing garbage from the line if there is any. */
    while (nIndex > 2 && wcschr(szTrim, szLine[nIndex-1])) {
        szLine[nIndex] = 0;
        nIndex--;
    }

    /* now the name SHOULD be the last thing on the line */
    pStr = wcsrchr(szLine, ' ');

    if (pStr)
        pStr++;
    else
        pStr = szLine;
    /*Suche nach -> */
    if (pStr > szLine + 2) {
        p = pStr; p--;
        while (p[0] == ' ') 
            p--;
        if (p != szLine) p--;
        if (p[0] == '-' && p[1] == '>' && p != szLine) { /*Verweis!*/
            p--;
            while (p[0] == ' ') p--;
            p[1] = 0;
            pStr = wcsrchr(szLine, ' ');
            if (pStr) pStr++;
            else pStr = szLine;
        }
    }
    return pStr;
}

/*Search with Date instead of last string*/
/*name may contain spaces on MAC ftpd!*/
WCHAR* FindNameUnix(WCHAR* szLine, int* link, BOOL longdatetype)
{
    int nIndex, i, j, incr;
    WCHAR *p, *p1, *p2, *minmonthpos, *monthpos;
    WCHAR linebuf[256];
    int num;
    WCHAR ch;
    BOOL ok, daybeforemonth, found;
    WCHAR* result;
    
    *link = 0;        /*No link*/
    nIndex = wcslen(szLine);
    p = szLine;
    /* strip trailing garbage from the line if there is any. */
    while (nIndex > 2 && wcschr(szTrim, szLine[nIndex-1])) {
        szLine[nIndex] = 0;
        nIndex--;
    }

    wcslcpy2(linebuf, szLine, countof(linebuf)-1);
    CharUpperBuffW(linebuf, wcslen(linebuf));
    p = linebuf;
    /* now look for the DATE! */

    minmonthpos = NULL;        /*Warning: file name may be a month name!*/
    for (i = 1; i <= 36; i++) {
        if (month[i][0] != 0) { /*Englisch und deutsch!*/
            p = linebuf;
            found = false;
            do {
                monthpos = wcsstr(p, month[i]);
                if (monthpos != NULL && monthpos != p) {
                    found = true; incr = 3;
                    if (wcschr(L" \t-, ", monthpos[3]) == NULL) {
                        if (wcschr(L" \t-, /, ", monthpos[4]) != NULL) {
                            found = true;
                            incr = 4;
                        } else found = false;
                    }
                    if (found) {
                        monthpos -= 2;
                        if (wcschr(L" \t-, /", monthpos[1]) == NULL) found = false;
                        daybeforemonth = monthpos[0] == '.';
                        monthpos += 2;
                        if (found) {
                            monthpos += incr;
                            for (j = 1; j <= 3; j++)       /*Max 3 Leerzeichen!*/
                                if (wcschr(L" \t-, /", monthpos[0]) != NULL) monthpos++;
                            if (isadigit(monthpos[0])) {
                                if (!daybeforemonth) {
                                    if (DecodeNumber(&monthpos, &num)) { /*Tag überspringen*/
                                        while (monthpos[0]==' ') monthpos++;
                                    } else found = false;
                                }
                                if (found && minmonthpos == NULL || monthpos < minmonthpos)
                                    minmonthpos = monthpos;
                            } else
                                found = false;
                        }
                    }
                }
                if (monthpos != NULL)
                    p = monthpos + 1;
            } while (!found && monthpos != NULL);
        }
    }
    /*Minmonthpos zeigt nun auf Jahr bzw. Zeit*/
    if (minmonthpos != NULL) {
        p = szLine + (minmonthpos - linebuf); /*Auf szLine zeigen!!!*/
        if (DecodeNumber(&p, &num)) {    /*Stunde bzw. Jahr überspringen*/
            p--;
            ch = p[0];
            p++;
            if (ch == ':' || (ch == '.' && isadigit(p[0])))
                {
                    ok = DecodeNumber(&p, &num); /*Zeit*/
                    if (longdatetype && ok)
                        p += 8;
                } else {                                     /*Jahr*/
                    ok = true;                               /*Novell: Zeit nach Jahr,  oft mit am/pm!*/
                    p2 = p;
                    while (p[0] == ' ') p++;
                    if (wcslen(p) > 5 && DecodeNumber(&p, &num)) { /*Stunde überspringen*/
                        p--;                     /*Achtung: nicht Namen als Zahl erkennen!*/
                        ch = p[0];
                        p++;
                        if (num <= 24 && num >= 0 && (ch == ':' || (ch == '.' && isadigit(p[0])))
                            && DecodeNumber(&p, &num)) { /*Zeit*/
                            p--;                     /*Achtung: nicht Namen als Zahl erkennen!*/
                            ch = p[0];
                            p++;
                            if (!((ch == ' ' || ch == 9) && (num < 60) && (num >= 0)))
                                p = p2;
                            else
                                /*Look for am/pm*/
                                if (p[1] == 'm' && p[2] == ' ' && (p[0] == 'a' || p[0] == 'p'))
                                    p += 2;
                        } else p = p2;
                    } else p = p2;
                }
            if (ok) {
                while (p[0]==' ') p++;
                result = p;
                p = wcsstr(p, L" ->");
                if (p != NULL) {
                    p2 = wcsrchr(p, '/');
                    if (p2 == NULL) p2 = p;
                    p1 = wcschr(p2, '.');
                    if (p1 != NULL && p1[1] == '.')
                        p1 = wcschr(p1 + 2, '.'); /*check for ../name*/
                    if (p1)
                        *link = 1;        /*probably a file*/
                    else
                        *link = 2;     /*probably a dir*/
                    p[0] = 0; /*Link!*/
                }
                return result;
            }
        }
    }
    return FindName(szLine); /*Do it the 'normal' way*/
}

__int64 GetSizeFromFront(WCHAR* lpstr)
{
    WCHAR *pstr, *lpsize;
    __int64 result = -1;
    pstr = lpstr;
    while (pstr[0] != ' ' && pstr[0] != 0) pstr++;      // Permissions
    while (pstr[0] == ' ') pstr++;                                    //Abstand
    if (isadigit(pstr[0])) {
        while (pstr[0] != ' ' && pstr[0] != 0) pstr++;// Zahl
        while (pstr[0] == ' ') pstr++;                            //Abstand
    }
    while (pstr[0] != ' ' && pstr[0] != 0) pstr++;      // Owner
    while (pstr[0] == ' ') pstr++;                                    // Abstand
    while (pstr[0] != ' ' && pstr[0] != 0) pstr++;      // Group
    while (pstr[0] == ' ') pstr++;                                    // Abstand
    if (isadigit(pstr[0])) {                     // Groesse gefunden!
        lpsize = pstr;
        while (isadigit(pstr[0])) pstr++;
        pstr[0] = 0;
        result = _wtoi64(lpsize);
    }
    return result;
}

void ReadDateTimeSizeUnix(WCHAR* lpS, FILETIME* datetime, __int64* sizefile)
{
    WCHAR buf[512];
    WCHAR *lp, *lp1, *lp2, *lpsize, *monthpos, *lpstr, *lpyear;
    SYSTEMTIME t;
    int i, j, code, incr;
    int num;
    BOOL found, daybeforemonth, hastime, longdatetype;
    WCHAR ch;

    memset(&t, 0, sizeof(t));
    hastime = true;
    wcslcpy2(buf, lpS, countof(buf)-1);
    lpstr = buf;
    datetime->dwHighDateTime = -1;
    datetime->dwLowDateTime = -1;
    *sizefile = -1;
    CharUpperBuffW(lpstr, wcslen(lpstr));
    t.wMonth = 0;
    monthpos = NULL;
    for (i = 1; i <= 36; i++) {
        if (month[i][0]) {
            monthpos = wcsstr(lpstr, month[i]);
            if (monthpos) {
                do {
                    found = true;
                    incr = 3;
                    if (monthpos != lpstr) {
                        if (wcschr(L" \t-, /", monthpos[3]) == NULL) {
                            found = false;
                            /*Deutsch kann auch sein 'Juni' 'März, ' etc.*/
                            /*-r-sr-xr-x     1 lp                bin                    16384 27. Juni 1997 enable
                            lr-xr-xr-t   1 root          sys                         20 16. März,  15:20 endif -> /opt/ansic/bin/endif*/
                            if (wcschr(L" \t-, /", monthpos[4]) != NULL) {
                                found = true;
                                incr = 4;
                            }
                        }
                        if (found) {
                            monthpos--;
                            if (wcschr(L" \t-, /", monthpos[0]) == NULL)
                                found = false;
                            monthpos++;
                        }
                    }
                    if (found) {
                        lp1 = monthpos;
                        lp1 += incr;
                        for (j = 1; j <= 3; j++)       /*Max 3 Leerzeichen!*/
                            if (wcschr(L" \t-, ./", lp1[0]) != NULL) lp1++;

                        if (!isadigit(lp1[0])) found = false;
                    }
                    if (!found)
                        monthpos = wcsstr(monthpos + 1, month[i]);
                } while (!found && monthpos != NULL);
                if (found) {
                    t.wMonth = i;
                    while (t.wMonth > 12)
                        t.wMonth -= 12;
                    break;
                }
            }
        }
    }
    if (monthpos) {
        monthpos--;
        monthpos[0] = 0;
        lpsize = monthpos;
        daybeforemonth = false;
        if (lpsize > buf) {
            lpsize--;
            if (lpsize[0] == '.') { /*Tag VOR Monat!!!*/
                daybeforemonth = true;
                lpsize[0] = 0;
                lpsize--;
                while (lpsize > lpstr && isadigit(lpsize[0]))
                    lpsize--;
                if (lpsize > lpstr)
                    lpsize++;
                t.wDay = _wtoi(lpsize);
                if (t.wDay>31) t.wDay = 0;
                if (lpsize > lpstr + 1) lpsize -= 2;
                lpsize[1] = 0;
            }
            while (lpsize > lpstr && lpsize[0] == ' ') lpsize--;
            lpsize[1] = 0;
            while (lpsize > lpstr && isadigit(lpsize[0])) lpsize--;
            if (!isadigit(lpsize[0])) lpsize++;
            *sizefile = _wtoi64(lpsize);
            code = 0;
        } else
            code = -1;
        if (code)
            *sizefile = GetSizeFromFront(lpstr);

        monthpos++;
        lp = wcschr(monthpos, ' ');
        if (lp) {
            while (lp[0] == ' ') lp++;
            if (daybeforemonth) {
                lp1 = lp;
            } else {
                lp1 = lp;
                while (isadigit(lp1[0])) lp1++;

                while (wcschr(L" \t-, ./", lp1[0]) != NULL) { /*lp1 zeigt nun auf Zeit bzw. Jahr*/
                    lp1[0] = 0;
                    lp1++;
                }
                t.wDay = _wtoi(lp);
                if (t.wDay > 31) { /*Zeit oder Jahr gefunden! -> Tag vor Monat*/
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
            /*Jahr oder Zeit suchen*/
            t.wSecond = 0;
            if (t.wDay > 0 && lp1[0]) {
                lp = wcschr(lp1, ' ');
                if (lp) {
                    lp[0] = 0;
                    lpyear = lp + 1;
                    lp2 = lp;
                    lp = wcschr(lp1, ':');
                    if (lp) {        /*Zeit*/
                        lp = wcstok(lp1, L":");
                        t.wHour = _wtoi(lp);
                        longdatetype = lp[5] == ':';
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
                            GetSystemTime(&st); /*Default to this year,  or the year before!*/
                            /*1 year before: problematisch,  wenn Server in anderer Zeitzone!
                                -> mindestens 2 Tage Unterschied*/
                            t.wYear = st.wYear;
                            if (t.wMonth > st.wMonth + 1 || (t.wMonth > st.wMonth && t.wDay > 2) ||
                                (t.wMonth == st.wMonth && t.wDay > st.wDay + 2))
                                t.wYear--;
                        }
                    } else {
                        t.wYear = _wtoi(lp1);
                        if (t.wYear < 100)
                            t.wYear += 1900;
                        if (t.wYear < 1980)
                            t.wYear += 100;
                        /*Novell: Zeit nach Jahr!*/
                        lp1 = lp2 + 1;
                        while (lp1[0] == ' ') lp1++;
                        if (DecodeNumber(&lp1, &num)) {  /*Stunde überspringen*/
                            t.wHour = num;
                            lp1--;
                            ch = lp1[0];
                            lp1++;
                            if (ch == ':' || (ch == '.' && isadigit(lp1[0])) &&
                                !DecodeNumber(&lp1, &num)) /*Zeit*/
                                lp1 = NULL;
                            else {
                                t.wMinute = num;
                                if (wcsncmp(lp1, L"PM ", 3)==0) { /*Zeit: pm*/
                                    if (t.wHour != 12)
                                        t.wHour += 12;
                                } else if (wcsncmp(lp1, L"AM ", 3)==0) /*Zeit: am*/
                                    if (t.wHour == 12) t.wHour = 0;
                            }
                        } else lp1 = NULL;
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
                    FILETIME datetime1;  //convert to system time
                    SystemTimeToFileTime(&t, &datetime1);
                    LocalFileTimeToFileTime(&datetime1, datetime);
                }
            }
        }
    } else { /*Month in other language*/
        *sizefile = GetSizeFromFront(lpstr);
    }
}

void ReadDateTimeSizeUser(WCHAR* lpStr, WCHAR* lpDate, FILETIME* datetime, __int64* sizefile)
{
    WCHAR* lpSize;
    if (lpDate) {
        lpSize = lpDate;
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
            t.wMonth  = get2digits(lpDate+4);
            t.wDay    = get2digits(lpDate+6);
            t.wHour   = get2digits(lpDate+9);
            t.wMinute = get2digits(lpDate+11);
            t.wSecond = get2digits(lpDate+13);
            t.wMilliseconds = 0;
            FILETIME datetime1;  //convert to system time
            SystemTimeToFileTime(&t, &datetime1);
            LocalFileTimeToFileTime(&datetime1, datetime);
        }
    }
}

BOOL ReadDirLineUNIX(WCHAR* lpStr, WCHAR* thename, int maxlen, __int64* sizefile, FILETIME* datetime, 
                     DWORD* attr, DWORD* UnixAttr, BOOL longdatetype)
{
    WCHAR *pstr, *pstr2, *Permissions;
    int linktest;

    /* assume UNIX ls format 
        if permissions start with 'd' its a directory */
    *attr = 0;
    *UnixAttr = 0;
    WCHAR testbuf[8];
    wcslcpy2(testbuf, lpStr, 6);
    wcsupr(testbuf);
    if (wcsncmp(testbuf, L"TOTAL", 5)==0)
        return false;

    Permissions = FindUnixPermissions(lpStr, UnixAttr); //Wegen CLIX-Unix!
    if (Permissions == NULL)
        return false;

    pstr2 = wcsstr(lpStr, L">>");   // user-defined date format ->easier to parse
    if (pstr2) {
        pstr = wcschr(pstr2, ' ');
        if (!pstr)
            return false;
        pstr++;
        ReadDateTimeSizeUser(lpStr, pstr2, datetime, sizefile);
    } else {
        pstr = FindNameUnix(lpStr, &linktest, longdatetype);
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
    wcslcpy2(thename, pstr, maxlen-1);
    pstr[0] = 0;      // Namen nicht als Monatsnamen erkennen!
    if (!pstr2)
        ReadDateTimeSizeUnix(lpStr, datetime, sizefile);
    if (*attr & (falink | FILE_ATTRIBUTE_DIRECTORY))
        *sizefile = 0;    //Wegen Progress!
    return thename[0] != 0 && wcscmp(thename, L".") != 0;
}

