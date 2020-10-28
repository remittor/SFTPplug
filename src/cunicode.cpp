#include "cunicode.h"

extern tProgressProcW ProgressProcW;
extern tLogProcW      LogProcW;
extern tRequestProcW  RequestProcW;


LPSTR walcopy(LPSTR outname, LPCWSTR inname, size_t maxlen) noexcept
{
    return walcopyCP(CP_ACP, outname, inname, maxlen);
}

LPSTR walcopyCP(int codepage, LPSTR outname, LPCWSTR inname, size_t maxlen) noexcept
{
    if (inname) {
        WideCharToMultiByte(codepage, 0, inname, -1, outname, (int)maxlen, NULL, NULL);
        outname[maxlen] = 0;
        return outname;
    }
    return NULL;
}

LPWSTR awlcopy(LPWSTR outname, LPCSTR inname, size_t maxlen) noexcept
{
    return awlcopyCP(CP_ACP, outname, inname, maxlen);
}

LPWSTR awlcopyCP(int codepage, LPWSTR outname, LPCSTR inname, size_t maxlen) noexcept
{
    if (inname) {
        MultiByteToWideChar(codepage, 0, inname, -1, outname, (int)maxlen);
        outname[maxlen] = 0;
        return outname;
    }
    return NULL;
}

LPWSTR wcslcpy(LPWSTR str1, LPCWSTR str2, size_t imaxlen) noexcept
{
    if (wcslen(str2) > imaxlen) {
        wcsncpy(str1, str2, imaxlen - 1);
        str1[imaxlen - 1] = 0;
    } else {
        wcscpy(str1, str2);
    }
    return str1;
}

LPWSTR wcslcat(LPWSTR str1, LPCWSTR str2, size_t imaxlen) noexcept
{
    size_t len1 = wcslen(str1);
    if (wcslen(str2) + len1 > imaxlen) {
        wcsncpy(str1 + len1, str2, imaxlen - 1 - len1);
        str1[imaxlen - 1] = 0;
    } else {
        wcscat(str1,str2);
    }
    return str1;
}

// return true if name wasn't cut
static bool MakeExtraLongNameW(LPWSTR outbuf, LPCWSTR inbuf, size_t maxlen) noexcept
{
    if (wcslen(inbuf) >= MAX_PATH) {
        wcslcpy(outbuf, L"\\\\?\\", maxlen);
        wcslcat(outbuf, inbuf, maxlen);
    } else {
        wcslcpy(outbuf, inbuf, maxlen);
    }
    return wcslen(inbuf) + 4 <= maxlen;
}

/***********************************************************************************************/

void copyfinddatawa(LPWIN32_FIND_DATA lpFindFileDataA, LPWIN32_FIND_DATAW lpFindFileDataW) noexcept
{
    walcopy(lpFindFileDataA->cAlternateFileName, lpFindFileDataW->cAlternateFileName, sizeof(lpFindFileDataW->cAlternateFileName)-1);
    walcopy(lpFindFileDataA->cFileName, lpFindFileDataW->cFileName, sizeof(lpFindFileDataW->cFileName)-1);
    lpFindFileDataA->dwFileAttributes = lpFindFileDataW->dwFileAttributes;
    lpFindFileDataA->ftCreationTime = lpFindFileDataW->ftCreationTime;
    lpFindFileDataA->ftLastAccessTime = lpFindFileDataW->ftLastAccessTime;
    lpFindFileDataA->ftLastWriteTime = lpFindFileDataW->ftLastWriteTime;
    lpFindFileDataA->nFileSizeHigh = lpFindFileDataW->nFileSizeHigh;
    lpFindFileDataA->nFileSizeLow = lpFindFileDataW->nFileSizeLow;
    lpFindFileDataA->dwReserved0 = lpFindFileDataW->dwReserved0;
    lpFindFileDataA->dwReserved1 = lpFindFileDataW->dwReserved1;
}

void copyfinddataaw(LPWIN32_FIND_DATAW lpFindFileDataW, LPWIN32_FIND_DATA lpFindFileDataA) noexcept
{
    awlcopy(lpFindFileDataW->cAlternateFileName, lpFindFileDataA->cAlternateFileName, countof(lpFindFileDataW->cAlternateFileName)-1);
    awlcopy(lpFindFileDataW->cFileName, lpFindFileDataA->cFileName, countof(lpFindFileDataW->cFileName)-1);
    lpFindFileDataW->dwFileAttributes = lpFindFileDataA->dwFileAttributes;
    lpFindFileDataW->ftCreationTime = lpFindFileDataA->ftCreationTime;
    lpFindFileDataW->ftLastAccessTime = lpFindFileDataA->ftLastAccessTime;
    lpFindFileDataW->ftLastWriteTime = lpFindFileDataA->ftLastWriteTime;
    lpFindFileDataW->nFileSizeHigh = lpFindFileDataA->nFileSizeHigh;
    lpFindFileDataW->nFileSizeLow = lpFindFileDataA->nFileSizeLow;
    lpFindFileDataW->dwReserved0 = lpFindFileDataA->dwReserved0;
    lpFindFileDataW->dwReserved1 = lpFindFileDataA->dwReserved1;
}

/***********************************************************************************************/

int ProgressProcT(int PluginNr, LPCWSTR SourceName, LPCWSTR TargetName, int PercentDone) noexcept
{
    if (ProgressProcW)
        return ProgressProcW(PluginNr, SourceName, TargetName, PercentDone);
    return 0;
}

void LogProcT(int PluginNr, int MsgType, LPCWSTR LogString) noexcept
{
    if (LogProcW)
        LogProcW(PluginNr, MsgType, LogString);
}


bool RequestProcT(int PluginNr, int RequestType, LPCWSTR CustomTitle, LPCWSTR CustomText, LPWSTR ReturnedText, size_t maxlen) noexcept
{
    if (RequestProcW) {
        BOOL retval = RequestProcW(PluginNr, RequestType, CustomTitle, CustomText, ReturnedText, (int)maxlen);
        return retval ? true : false;
    }
    return false;
}

BOOL CopyFileT(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, BOOL bFailIfExists) noexcept
{
    WCHAR wbuf1[wdirtypemax];
    if (!MakeExtraLongNameW(wbuf1, lpExistingFileName, wdirtypemax - 1))
        return FALSE;
    WCHAR wbuf2[wdirtypemax];
    if (!MakeExtraLongNameW(wbuf2, lpNewFileName, wdirtypemax - 1))
        return FALSE;
    return CopyFileW(wbuf1, wbuf2, bFailIfExists);
}

BOOL CreateDirectoryT(LPCWSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes) noexcept
{
    WCHAR wbuf[wdirtypemax];
    if (!MakeExtraLongNameW(wbuf, lpPathName, wdirtypemax - 1))
        return FALSE;
    return CreateDirectoryW(wbuf, lpSecurityAttributes);
}

BOOL RemoveDirectoryT(LPCWSTR lpPathName) noexcept
{
    WCHAR wbuf[wdirtypemax];
    if (!MakeExtraLongNameW(wbuf, lpPathName, wdirtypemax - 1))
        return FALSE;
    return RemoveDirectoryW(wbuf);
}

BOOL DeleteFileT(LPCWSTR lpFileName) noexcept
{
    WCHAR wbuf[wdirtypemax];
    if (!MakeExtraLongNameW(wbuf, lpFileName, wdirtypemax - 1))
        return FALSE;
    return DeleteFileW(wbuf);
}

BOOL MoveFileT(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName) noexcept
{
    WCHAR wbuf1[wdirtypemax];
    if (!MakeExtraLongNameW(wbuf1, lpExistingFileName, wdirtypemax - 1))
        return FALSE;
    WCHAR wbuf2[wdirtypemax];
    if (!MakeExtraLongNameW(wbuf2, lpNewFileName, wdirtypemax - 1))
        return FALSE;
    return MoveFileW(wbuf1, wbuf2);
}

BOOL SetFileAttributesT(LPCWSTR lpFileName, DWORD dwFileAttributes) noexcept
{
    WCHAR wbuf[wdirtypemax];
    if (!MakeExtraLongNameW(wbuf, lpFileName, wdirtypemax - 1))
        return FALSE;
    return SetFileAttributesW(wbuf, dwFileAttributes);
}

HANDLE CreateFileT(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, 
                   LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, 
                   DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) noexcept
{
    WCHAR wbuf[wdirtypemax];
    if (!MakeExtraLongNameW(wbuf, lpFileName, wdirtypemax - 1))
        return INVALID_HANDLE_VALUE;
    return CreateFileW(wbuf, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

UINT ExtractIconExT(LPCWSTR lpszFile, int nIconIndex, HICON * phiconLarge, HICON * phiconSmall, UINT nIcons) noexcept
{
    // Unfortunately this function cannot handle names longer than 259 characters
    return ExtractIconExW(lpszFile, nIconIndex, phiconLarge, phiconSmall, nIcons);
}

HANDLE FindFirstFileT(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData) noexcept
{
    WCHAR wbuf[wdirtypemax];
    if (!MakeExtraLongNameW(wbuf, lpFileName, wdirtypemax - 1))
        return INVALID_HANDLE_VALUE;
    return FindFirstFileW(wbuf, lpFindFileData);
}

BOOL FindNextFileT(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData) noexcept
{
    return FindNextFileW(hFindFile, lpFindFileData);
}

