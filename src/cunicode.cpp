#include <windows.h>
#include "fsplugin.h"
#include "cunicode.h"

extern tProgressProc ProgressProc;
extern tLogProc LogProc;
extern tRequestProc RequestProc;
extern tProgressProcW ProgressProcW;
extern tLogProcW LogProcW;
extern tRequestProcW RequestProcW;

char usysychecked = 0;

BOOL usys()
{
    if (!usysychecked) {
        OSVERSIONINFO vx;
        vx.dwOSVersionInfoSize = sizeof(vx);
        GetVersionEx(&vx);
        if (vx.dwPlatformId == VER_PLATFORM_WIN32_NT)
            usysychecked = 1;
        else
            usysychecked = 2;
    }
    return (usysychecked == 1);
}

char* walcopy(char* outname, WCHAR* inname, int maxlen)
{
    if (inname) {
        WideCharToMultiByte(CP_ACP, 0, inname, -1, outname, maxlen, NULL, NULL);
        outname[maxlen] = 0;
        return outname;
    }
    return NULL;
}

char* walcopyCP(int codepage, char* outname, WCHAR* inname, int maxlen)
{
    if (inname) {
        WideCharToMultiByte(codepage, 0, inname, -1, outname, maxlen, NULL, NULL);
        outname[maxlen] = 0;
        return outname;
    }
    return NULL;
}

WCHAR* awlcopy(WCHAR* outname, char* inname, int maxlen)
{
    if (inname) {
        MultiByteToWideChar(CP_ACP, 0, inname, -1, outname, maxlen);
        outname[maxlen] = 0;
        return outname;
    }
    return NULL;
}

WCHAR* awlcopyCP(int codepage, WCHAR* outname, char* inname, int maxlen)
{
    if (inname) {
        MultiByteToWideChar(codepage, 0, inname, -1, outname, maxlen);
        outname[maxlen] = 0;
        return outname;
    }
    return NULL;
}

WCHAR* wcslcpy(WCHAR *str1, const WCHAR *str2, int imaxlen)
{
    if ((int)wcslen(str2) >= imaxlen - 1) {
        wcsncpy(str1, str2, imaxlen - 1);
        str1[imaxlen - 1] = 0;
    } else {
        wcscpy(str1, str2);
    }
    return str1;
}

WCHAR* wcslcat(wchar_t *str1, const WCHAR *str2, int imaxlen)
{
    int l1 = (int)wcslen(str1);
    if ((int)wcslen(str2) + l1 >= imaxlen - 1) {
        wcsncpy(str1 + l1, str2, imaxlen - 1 - l1);
        str1[imaxlen - 1] = 0;
    } else {
        wcscat(str1,str2);
    }
    return str1;
}

// return true if name wasn't cut
BOOL MakeExtraLongNameW(WCHAR* outbuf, const WCHAR* inbuf, int maxlen)
{
    if (wcslen(inbuf) > 259) {
        wcslcpy(outbuf, L"\\\\?\\", maxlen);
        wcslcat(outbuf, inbuf, maxlen);
    } else {
        wcslcpy(outbuf, inbuf, maxlen);
    }
    return (int)wcslen(inbuf) + 4 <= maxlen;
}

/***********************************************************************************************/

void copyfinddatawa(WIN32_FIND_DATA *lpFindFileDataA,WIN32_FIND_DATAW *lpFindFileDataW)
{
    walcopy(lpFindFileDataA->cAlternateFileName, lpFindFileDataW->cAlternateFileName, sizeof(lpFindFileDataW->cAlternateFileName)-1);
    walcopy(lpFindFileDataA->cFileName, lpFindFileDataW->cFileName, sizeof(lpFindFileDataW->cFileName)-1);
    lpFindFileDataA->dwFileAttributes = lpFindFileDataW->dwFileAttributes;
    lpFindFileDataA->dwReserved0 = lpFindFileDataW->dwReserved0;
    lpFindFileDataA->dwReserved1 = lpFindFileDataW->dwReserved1;
    lpFindFileDataA->ftCreationTime = lpFindFileDataW->ftCreationTime;
    lpFindFileDataA->ftLastAccessTime = lpFindFileDataW->ftLastAccessTime;
    lpFindFileDataA->ftLastWriteTime = lpFindFileDataW->ftLastWriteTime;
    lpFindFileDataA->nFileSizeHigh = lpFindFileDataW->nFileSizeHigh;
    lpFindFileDataA->nFileSizeLow = lpFindFileDataW->nFileSizeLow;
}

void copyfinddataaw(WIN32_FIND_DATAW *lpFindFileDataW, WIN32_FIND_DATA *lpFindFileDataA)
{
    awlcopy(lpFindFileDataW->cAlternateFileName, lpFindFileDataA->cAlternateFileName, countof(lpFindFileDataW->cAlternateFileName)-1);
    awlcopy(lpFindFileDataW->cFileName, lpFindFileDataA->cFileName, countof(lpFindFileDataW->cFileName)-1);
    lpFindFileDataW->dwFileAttributes = lpFindFileDataA->dwFileAttributes;
    lpFindFileDataW->dwReserved0 = lpFindFileDataA->dwReserved0;
    lpFindFileDataW->dwReserved1 = lpFindFileDataA->dwReserved1;
    lpFindFileDataW->ftCreationTime = lpFindFileDataA->ftCreationTime;
    lpFindFileDataW->ftLastAccessTime = lpFindFileDataA->ftLastAccessTime;
    lpFindFileDataW->ftLastWriteTime = lpFindFileDataA->ftLastWriteTime;
    lpFindFileDataW->nFileSizeHigh = lpFindFileDataA->nFileSizeHigh;
    lpFindFileDataW->nFileSizeLow = lpFindFileDataA->nFileSizeLow;
}

/***********************************************************************************************/

int ProgressProcT(int PluginNr, WCHAR* SourceName, WCHAR* TargetName, int PercentDone)
{
    if (ProgressProcW)
        return ProgressProcW(PluginNr, SourceName, TargetName, PercentDone);
    
    if (ProgressProc) {
        char buf1[MAX_PATH], buf2[MAX_PATH];
        return ProgressProc(PluginNr, wafilenamecopy(buf1, SourceName), wafilenamecopy(buf2, TargetName), PercentDone);
    }
    return 0;
}

void LogProcT(int PluginNr, int MsgType, WCHAR* LogString)
{
    if (LogProcW) {
        LogProcW(PluginNr, MsgType, LogString);
    } else if (LogProc) {
        char buf[1024];
        LogProc(PluginNr, MsgType, walcopy(buf, LogString, sizeof(buf)-1));
    }
}


BOOL RequestProcT(int PluginNr, int RequestType, WCHAR* CustomTitle, WCHAR* CustomText, WCHAR* ReturnedText, int maxlen)
{
    if (RequestProcW)
        return RequestProcW(PluginNr, RequestType, CustomTitle, CustomText, ReturnedText, maxlen);

    if (RequestProc) {
        char buf1[MAX_PATH], buf2[MAX_PATH], buf3[MAX_PATH];
        char* preturn = wafilenamecopy(buf3, ReturnedText);
        BOOL retval = RequestProc(PluginNr, RequestType, wafilenamecopy(buf1, CustomTitle), wafilenamecopy(buf2, CustomText), preturn, maxlen);
        if (retval && preturn)
            awlcopy(ReturnedText, preturn, maxlen);
        return retval;
    }
    return false;
}

BOOL CopyFileT(WCHAR* lpExistingFileName, WCHAR* lpNewFileName, BOOL bFailIfExists)
{
    if (usys()) {
        WCHAR wbuf1[wdirtypemax], wbuf2[wdirtypemax];
        if (MakeExtraLongNameW(wbuf1, lpExistingFileName, wdirtypemax-1) &&
            MakeExtraLongNameW(wbuf2, lpNewFileName, wdirtypemax-1))
            return CopyFileW(wbuf1, wbuf2, bFailIfExists);
    } else {
        char buf1[MAX_PATH], buf2[MAX_PATH];
        return CopyFile(wafilenamecopy(buf1, lpExistingFileName), wafilenamecopy(buf2, lpNewFileName), bFailIfExists);
    }
    return false;
}

BOOL CreateDirectoryT(WCHAR* lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
    if (usys()) {
        WCHAR wbuf[wdirtypemax];
        if (MakeExtraLongNameW(wbuf, lpPathName, wdirtypemax-1))
            return CreateDirectoryW(wbuf, lpSecurityAttributes);
    } else {
        char buf[MAX_PATH];
        return CreateDirectory(wafilenamecopy(buf, lpPathName), lpSecurityAttributes);
    }
    return false;
}

BOOL RemoveDirectoryT(WCHAR* lpPathName)
{
    if (usys()) {
        WCHAR wbuf[wdirtypemax];
        if (MakeExtraLongNameW(wbuf, lpPathName, wdirtypemax-1))
            return RemoveDirectoryW(wbuf);
    } else {
        char buf[MAX_PATH];
        return RemoveDirectory(wafilenamecopy(buf, lpPathName));
    }
    return false;
}

BOOL DeleteFileT(WCHAR* lpFileName)
{
    if (usys()) {
        WCHAR wbuf[wdirtypemax];
        if (MakeExtraLongNameW(wbuf, lpFileName, wdirtypemax-1))
            return DeleteFileW(wbuf);
    } else {
        char buf[MAX_PATH];
        return DeleteFile(wafilenamecopy(buf, lpFileName));
    }
    return false;
}

BOOL MoveFileT(WCHAR* lpExistingFileName, WCHAR* lpNewFileName)
{
    if (usys()) {
        WCHAR wbuf1[wdirtypemax], wbuf2[wdirtypemax];
        if (MakeExtraLongNameW(wbuf1, lpExistingFileName, wdirtypemax-1) &&
            MakeExtraLongNameW(wbuf2, lpNewFileName, wdirtypemax-1))
            return MoveFileW(wbuf1, wbuf2);
    } else {
        char buf1[MAX_PATH], buf2[MAX_PATH];
        return MoveFile(wafilenamecopy(buf1, lpExistingFileName), wafilenamecopy(buf2, lpNewFileName));
    }
    return false;
}

BOOL SetFileAttributesT(WCHAR* lpFileName, DWORD dwFileAttributes)
{
    if (usys()) {
        WCHAR wbuf[wdirtypemax];
        if (MakeExtraLongNameW(wbuf, lpFileName, wdirtypemax-1))
            return SetFileAttributesW(wbuf, dwFileAttributes);
    } else {
        char buf[MAX_PATH];
        return SetFileAttributes(wafilenamecopy(buf, lpFileName), dwFileAttributes);
    }
    return false;
}

HANDLE CreateFileT(WCHAR* lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, 
                   LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, 
                   DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    if (usys()) {
        WCHAR wbuf[wdirtypemax];
        if (MakeExtraLongNameW(wbuf, lpFileName, wdirtypemax-1))
            return CreateFileW(wbuf, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    } else {
        char buf[MAX_PATH];
        char* fn = wafilenamecopy(buf, lpFileName);
        return CreateFile(fn, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    }
    return INVALID_HANDLE_VALUE;
}

UINT ExtractIconExT(WCHAR* lpszFile, int nIconIndex, HICON *phiconLarge, HICON *phiconSmall, UINT nIcons)
{
    if (usys()) {  // Unfortunately this function cannot handle names longer than 259 characters
        return ExtractIconExW(lpszFile, nIconIndex, phiconLarge, phiconSmall, nIcons);
    } else {
        char buf[MAX_PATH];
        return ExtractIconEx(wafilenamecopy(buf, lpszFile), nIconIndex, phiconLarge, phiconSmall, nIcons);
    }
}

HANDLE FindFirstFileT(WCHAR* lpFileName, LPWIN32_FIND_DATAW lpFindFileData)
{
    if (usys()) {
        WCHAR wbuf[wdirtypemax];
        if (MakeExtraLongNameW(wbuf, lpFileName, wdirtypemax-1))
            return FindFirstFileW(wbuf, lpFindFileData);
    } else {
        char buf[MAX_PATH];
        WIN32_FIND_DATA FindFileDataA;
        HANDLE retval = FindFirstFile(wafilenamecopy(buf, lpFileName), &FindFileDataA);
        if (retval != INVALID_HANDLE_VALUE) {
          awlcopy(lpFindFileData->cAlternateFileName, FindFileDataA.cAlternateFileName, countof(lpFindFileData->cAlternateFileName)-1);
          awlcopy(lpFindFileData->cFileName, FindFileDataA.cFileName, countof(lpFindFileData->cFileName)-1);
          lpFindFileData->dwFileAttributes = FindFileDataA.dwFileAttributes;
          lpFindFileData->dwReserved0 = FindFileDataA.dwReserved0;
          lpFindFileData->dwReserved1 = FindFileDataA.dwReserved1;
          lpFindFileData->ftCreationTime = FindFileDataA.ftCreationTime;
          lpFindFileData->ftLastAccessTime = FindFileDataA.ftLastAccessTime;
          lpFindFileData->ftLastWriteTime = FindFileDataA.ftLastWriteTime;
          lpFindFileData->nFileSizeHigh = FindFileDataA.nFileSizeHigh;
          lpFindFileData->nFileSizeLow = FindFileDataA.nFileSizeLow;
        }
        return retval;
    }
    return INVALID_HANDLE_VALUE;
}

BOOL FindNextFileT(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData)
{
    if (usys()) {
        return FindNextFileW(hFindFile, lpFindFileData);
    }
    WIN32_FIND_DATA FindFileDataA;
    memset(&FindFileDataA, 0, sizeof(FindFileDataA));
    BOOL retval = FindNextFile(hFindFile, &FindFileDataA);
    if (retval) {
        awlcopy(lpFindFileData->cAlternateFileName, FindFileDataA.cAlternateFileName, countof(lpFindFileData->cAlternateFileName)-1);
        awlcopy(lpFindFileData->cFileName, FindFileDataA.cFileName, countof(lpFindFileData->cFileName)-1);
        lpFindFileData->dwFileAttributes = FindFileDataA.dwFileAttributes;
        lpFindFileData->dwReserved0 = FindFileDataA.dwReserved0;
        lpFindFileData->dwReserved1 = FindFileDataA.dwReserved1;
        lpFindFileData->ftCreationTime = FindFileDataA.ftCreationTime;
        lpFindFileData->ftLastAccessTime = FindFileDataA.ftLastAccessTime;
        lpFindFileData->ftLastWriteTime = FindFileDataA.ftLastWriteTime;
        lpFindFileData->nFileSizeHigh = FindFileDataA.nFileSizeHigh;
        lpFindFileData->nFileSizeLow = FindFileDataA.nFileSizeLow;
    }
    return retval;
}

