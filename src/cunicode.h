#pragma once

#include <windows.h>
#include "fsplugin.h"
#include "utils.h"
#include "CVTUTF.H"


#define wdirtypemax 1024

__forceinline
bool usys() noexcept
{
    return true;   /* minimal requirements: WinXP and TC 7.51 */
}

LPWSTR wcslcpy(LPWSTR str1, LPCWSTR str2, size_t imaxlen) noexcept;
LPWSTR wcslcat(LPWSTR str1, LPCWSTR str2, size_t imaxlen) noexcept;
LPSTR  walcopy(LPSTR outname, LPCWSTR inname, size_t maxlen) noexcept;
LPSTR  walcopyCP(int codepage, LPSTR outname, LPCWSTR inname, size_t maxlen) noexcept;
LPWSTR awlcopy(LPWSTR outname, LPCSTR inname, size_t maxlen) noexcept;
LPWSTR awlcopyCP(int codepage, LPWSTR outname, LPCSTR inname, size_t maxlen) noexcept;

int ConvUTF16toUTF8(LPCWSTR inbuf, size_t inlen, LPSTR outbuf, size_t outmax, bool nullterm = true) noexcept;
int ConvUTF8toUTF16(LPCSTR inbuf, size_t inlen, LPWSTR outbuf, size_t outmax, bool nullterm = true) noexcept;

#define wafilenamecopy(outname, inname)  walcopy(outname, inname, _countof(outname)-1)
#define awfilenamecopy(outname, inname)  awlcopy(outname, inname, _countof(outname)-1)

void copyfinddatawa(LPWIN32_FIND_DATA  lpFindFileDataA, LPWIN32_FIND_DATAW lpFindFileDataW) noexcept;
void copyfinddataaw(LPWIN32_FIND_DATAW lpFindFileDataW, LPWIN32_FIND_DATA  lpFindFileDataA) noexcept;

int  ProgressProcT(int PluginNr, LPCWSTR SourceName, LPCWSTR TargetName, int PercentDone) noexcept;
void LogProcT(int PluginNr, int MsgType, LPCWSTR LogString) noexcept;
bool RequestProcT(int PluginNr, int RequestType, LPCWSTR CustomTitle, LPCWSTR CustomText, LPWSTR ReturnedText, size_t maxlen) noexcept;

BOOL CopyFileT(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, BOOL bFailIfExists) noexcept;
BOOL CreateDirectoryT(LPCWSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes) noexcept;
BOOL RemoveDirectoryT(LPCWSTR lpPathName) noexcept;
BOOL DeleteFileT(LPCWSTR lpFileName) noexcept;
BOOL MoveFileT(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName) noexcept;
BOOL SetFileAttributesT(LPCWSTR lpFileName, DWORD dwFileAttributes) noexcept;
HANDLE CreateFileT(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, 
                   LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, 
                   DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) noexcept;

UINT ExtractIconExT(LPCWSTR lpszFile, int nIconIndex, HICON * phiconLarge, HICON * phiconSmall, UINT nIcons) noexcept;

HANDLE FindFirstFileT(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData) noexcept;
BOOL FindNextFileT(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData) noexcept;

