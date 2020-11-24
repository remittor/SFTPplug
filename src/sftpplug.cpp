// sertransplg.cpp : Defines the entry point for the DLL application.
//

#include "sftpplug.h"
#include <stdlib.h>
#include "utils.h"
#include "res/resource.h"
#include "sftpfunc.h"
#include "multiserver.h"
#include "cunicode.h"

HINSTANCE hinst = NULL;
HWND hWndMain = NULL;

char inifilename[MAX_PATH] = "sftpplug.ini";
char pluginname[] = "SFTP";
char defrootname[] = "Secure FTP";

char s_f7newconnection[32];
char s_quickconnect[32];
WCHAR s_f7newconnectionW[32];
WCHAR s_quickconnectW[32];

bool disablereading = false;   // disable reading of subdirs to delete whole drives
bool freportconnect = true;    // report connect to caller only on first connect
bool CryptCheckPass = false;   // check 'store password encrypted' by default

int PluginNumber = 0;
int CryptoNumber = 0;
DWORD mainthreadid = 0;
tProgressProc  ProgressProc = NULL;
tProgressProcW ProgressProcW = NULL;
tLogProc       LogProc = NULL;
tLogProcW      LogProcW = NULL;
tRequestProc   RequestProc = NULL;
tRequestProcW  RequestProcW = NULL;
tCryptProc     CryptProc = NULL;


/* FIXME: replace returnrd type to enum FS_TASK_CONTINUE / FS_TASK_ABORTED */
static bool MessageLoop(SERVERID serverid) noexcept
{
    bool aborted = false;
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (!g_wfx.m_cb.ProgressProc)
        return false;
    if (ConnectSettings && get_ticks_between(ConnectSettings->lastpercenttime) > 250) {   /* FIXME: magic number! */
        // important: also call AFTER soft_aborted is true!!!
        aborted = (0 != ProgressProc(PluginNumber, NULL, NULL, ConnectSettings->lastpercent));
        // allow abort with Escape when there is no progress dialog!
        ConnectSettings->lastpercenttime = get_sys_ticks();
    }
    return aborted;
}

void LogMsg(LPCSTR fmt, ...) noexcept
{
    char buf[512];
    va_list argptr;
    va_start(argptr, fmt);
    int len = _vsnprintf(buf, _countof(buf)-2, fmt, argptr);
    va_end(argptr);
    if (len < 0) {
        strcpy_s(buf, _countof(buf), "<INCORRECT-INPUT-DATA> ");
        strcat_s(buf, _countof(buf), fmt);
    } else {
        buf[len] = 0;
    }
    LogProc(PluginNumber, MSGTYPE_DETAILS, buf);
}

void ShowStatus(LPCSTR status) noexcept
{
    if (LogProc)
        LogProc(PluginNumber, MSGTYPE_DETAILS, status);
}

void ShowStatusW(LPCWSTR status) noexcept
{
    LogProcT(PluginNumber, MSGTYPE_DETAILS, status);
}

/* FIXME: replace returnrd type to enum FS_TASK_CONTINUE / FS_TASK_ABORTED */
bool UpdatePercentBar(SERVERID serverid, int percent) noexcept
{
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (ConnectSettings)
        ConnectSettings->lastpercent = percent;  // used for MessageLoop below

    return MessageLoop(serverid);  // This actually sets the percent bar!
}

static pConnectSettings GetServerIdAndRelativePathFromPath(LPCSTR Path, LPSTR RelativePath, size_t maxlen)
{
    char DisplayName[wdirtypemax];
    GetDisplayNameFromPath(Path, DisplayName, countof(DisplayName)-1);
    SERVERID serverid = GetServerIdFromName(DisplayName, GetCurrentThreadId());
    if (serverid) {
        RelativePath[0] = 0;
        LPCSTR p = Path;
        while (p[0] == '\\' || p[0] == '/')  // skip initial slash
            p++;
        while (p[0] != 0 && p[0] != '\\' && p[0] != '/') // skip path
            p++;
        strlcat(RelativePath, p, maxlen);
        if (RelativePath[0] == 0)
            strlcpy(RelativePath, "\\", maxlen-1);
    } else if (maxlen)
        strlcpy(RelativePath, "\\", maxlen-1);
    return (pConnectSettings)serverid;
}

static pConnectSettings GetServerIdAndRelativePathFromPathW(LPCWSTR Path, LPWSTR RelativePath, size_t maxlen)
{
    char DisplayName[wdirtypemax], PathA[wdirtypemax];
    walcopy(PathA, Path, countof(PathA)-1);
    GetDisplayNameFromPath(PathA, DisplayName, countof(DisplayName)-1);
    SERVERID serverid = GetServerIdFromName(DisplayName, GetCurrentThreadId());
    if (serverid) {
        RelativePath[0] = 0;
        LPCWSTR p = Path;
        while (p[0] == '\\' || p[0] == '/')  // skip initial slash
            p++;
        while (p[0] != 0 && p[0] != '\\' && p[0] != '/') // skip path
            p++;
        wcslcat(RelativePath, p, maxlen);
        if (RelativePath[0] == 0)
            wcslcpy(RelativePath, L"\\", maxlen-1);
    } else if (maxlen)
        wcslcpy(RelativePath, L"\\", maxlen-1);
    return (pConnectSettings)serverid;
}

__forceinline
static void ResetLastPercent(pConnectSettings ConnectSettings)
{
    if (ConnectSettings)
        ConnectSettings->lastpercent = 0;
}

static bool is_full_name(LPCSTR path)
{
    return path && path[0] && path[1] && strchr(path + 1, '\\');
}

static bool is_full_name(LPCWSTR path)
{
    return path && path[0] && path[1] && wcschr(path + 1, L'\\');
}

static bool is_full_name(LPWSTR path)
{
    return path && path[0] && path[1] && wcschr(path + 1, L'\\');
}

static LPWSTR cut_srv_name(LPWSTR path)
{
    if (path && path[0] && path[1]) {
        LPWSTR p = wcschr(path + 1, L'\\');
        if (p) {
            p[0] = 0;
            return path + 1;
        }
    }
    return NULL;
}

static bool FileExistsT(LPCWSTR LocalName)
{
    WIN32_FIND_DATAW s;
    HANDLE findhandle = FindFirstFileT(LocalName, &s);
    if (!findhandle || findhandle == INVALID_HANDLE_VALUE)
        return false;
    FindClose(findhandle);
    return true;
}

static void RemoveInalidChars(LPSTR p)
{
    while (p[0]) {
        if ((UCHAR)p[0] < 32)
            p[0] = ' ';
        else if (p[0] == ':' || p[0] == '|' || p[0] == '*' || p[0] == '?' || p[0] == '\\' || p[0] == '/' || p[0] == '"')
            p[0] = '_';
        p++;
    }
}

static void RemoveInalidCharsW(LPWSTR p)
{
    while (p[0]) {
        if ((WORD)p[0] < 32)
            p[0] = L' ';
        else if (p[0] == L':' || p[0] == L'|' || p[0] == L'*' || p[0] == L'?' || p[0] == L'\\' || p[0] == L'/' || p[0] == L'"')
            p[0] = L'_';
        p++;
    }
}

BOOL WINAPI FsRemoveDirW(LPCWSTR RemoteName)
{
    if (is_full_name(RemoteName)) {
        WCHAR remotedir[wdirtypemax];
        pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir, countof(remotedir)-1);
        if (serverid == NULL)
            return false;
        ResetLastPercent(serverid);
        int rc = SftpDeleteFileW(serverid, remotedir, true);
        return (rc == SFTP_OK) ? true : false;
    }
    return false;
}

BOOL WINAPI FsRemoveDir(LPCSTR RemoteName)
{
    WCHAR RemoteNameW[wdirtypemax];
    return FsRemoveDirW(awfilenamecopy(RemoteNameW, RemoteName));
}

/* FIXME: make func FsSetAttrW */

BOOL WINAPI FsSetAttr(LPCSTR RemoteName, int NewAttr)
{
    char remotedir[wdirtypemax];
    pConnectSettings serverid = GetServerIdAndRelativePathFromPath(RemoteName, remotedir, countof(remotedir)-1);
    if (serverid == NULL)
        return false;
    ResetLastPercent(serverid);
    int rc = SftpSetAttr(serverid, remotedir, NewAttr);
    return (rc == SFTP_OK) ? true : false;
}

BOOL WINAPI FsSetTimeW(LPCWSTR RemoteName, LPFILETIME CreationTime, LPFILETIME LastAccessTime, LPFILETIME LastWriteTime)
{
    WCHAR remotedir[wdirtypemax];
    pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir, countof(remotedir)-1);
    if (serverid == NULL)
        return false;
    ResetLastPercent(serverid);
    int rc = SftpSetDateTimeW(serverid, remotedir, LastWriteTime);
    return (rc == SFTP_OK) ? true : false;
}

BOOL WINAPI FsSetTime(LPCSTR RemoteName, LPFILETIME CreationTime, LPFILETIME LastAccessTime, LPFILETIME LastWriteTime)
{
    WCHAR RemoteNameW[wdirtypemax];
    return FsSetTimeW(awfilenamecopy(RemoteNameW, RemoteName), CreationTime, LastAccessTime, LastWriteTime);
}

/* FIXME: make func FsStatusInfoW */

void WINAPI FsStatusInfo(LPCSTR RemoteDir, int InfoStartEnd, int InfoOperation)
{
    if (strlen(RemoteDir) < 2)
        if (InfoOperation == FS_STATUS_OP_DELETE || InfoOperation == FS_STATUS_OP_RENMOV_MULTI)
            disablereading = (InfoStartEnd == FS_STATUS_START) ? true : false;

    if (InfoOperation == FS_STATUS_OP_GET_MULTI_THREAD || InfoOperation == FS_STATUS_OP_PUT_MULTI_THREAD) {
        if (InfoStartEnd != FS_STATUS_START) {
            FsDisconnect(RemoteDir);
            return;
        }
        char DisplayName[MAX_PATH];
        LPSTR oldpass = NULL;
        GetDisplayNameFromPath(RemoteDir, DisplayName, sizeof(DisplayName)-1);
        // get password from main thread
        pConnectSettings oldserverid = (pConnectSettings)GetServerIdFromName(DisplayName, mainthreadid);
        if (oldserverid) {
            oldpass = oldserverid->password;
            if (!oldpass[0])
                oldpass = NULL;
        }
        SERVERID serverid = SftpConnectToServer(DisplayName, inifilename, oldpass);
        if (serverid)
            SetServerIdForName(DisplayName, serverid);
    }
}

int WINAPI FsExtractCustomIcon(LPCSTR RemoteName, int ExtractFlags, HICON * TheIcon)
{
    if (strlen(RemoteName) > 1) {
        if (!is_full_name(RemoteName)) {   // a server!
            if (_stricmp(RemoteName + 1, s_f7newconnection) != 0) {
                char remotedir[wdirtypemax];
                SERVERID serverid = GetServerIdAndRelativePathFromPath(RemoteName, remotedir, sizeof(remotedir)-1);
                /* FIXME: check serverid with NULL */
                bool sm = (ExtractFlags & FS_ICONFLAG_SMALL) != 0;
                // show different icon when connected!
                LPCSTR lpIconName;
                if (serverid == NULL)
                    lpIconName = MAKEINTRESOURCEA(sm ? IDI_ICON1SMALL : IDI_ICON1);
                else
                    lpIconName = MAKEINTRESOURCEA(sm ? IDI_ICON2SMALL : IDI_ICON2);
                *TheIcon = LoadIconA(hinst, lpIconName);
                return FS_ICON_EXTRACTED;
            }
        }
    } 
    return FS_ICON_USEDEFAULT;
}

int WINAPI FsServerSupportsChecksumsW(LPCWSTR RemoteName)
{
    WCHAR remotedir[wdirtypemax];
    pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir, countof(remotedir)-1);
    if (serverid == NULL)
        return 0;
    ResetLastPercent(serverid);
    return SftpServerSupportsChecksumsW(serverid, remotedir);
}

int WINAPI FsServerSupportsChecksums(LPCSTR RemoteName)
{
    WCHAR RemoteNameW[wdirtypemax];
    return FsServerSupportsChecksumsW(awfilenamecopy(RemoteNameW, RemoteName));
}

HANDLE WINAPI FsStartFileChecksumW(int ChecksumType, LPCWSTR RemoteName)
{
    WCHAR remotedir[wdirtypemax];
    pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir, countof(remotedir)-1);
    if (serverid == NULL)
        return NULL;
    ResetLastPercent(serverid);
    return SftpStartFileChecksumW(ChecksumType, serverid, remotedir);
}

HANDLE WINAPI FsStartFileChecksum(int ChecksumType, LPCSTR RemoteName)
{
    WCHAR RemoteNameW[wdirtypemax];
    return FsStartFileChecksumW(ChecksumType, awfilenamecopy(RemoteNameW, RemoteName));
}


int WINAPI FsGetFileChecksumResultW(BOOL WantResult, HANDLE ChecksumHandle, LPCWSTR RemoteName, LPSTR checksum, int maxlen)
{
    WCHAR remotedir[wdirtypemax];
    pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir, countof(remotedir)-1);
    if (serverid == NULL)
        return 0;
    ResetLastPercent(serverid);
    return SftpGetFileChecksumResultW(!!WantResult, ChecksumHandle, serverid, checksum, maxlen);
}

int WINAPI FsGetFileChecksumResult(BOOL WantResult, HANDLE ChecksumHandle, LPCSTR RemoteName, LPSTR checksum, int maxlen)
{
    WCHAR RemoteNameW[wdirtypemax];
    return FsGetFileChecksumResultW(!!WantResult, ChecksumHandle, awfilenamecopy(RemoteNameW, RemoteName), checksum, maxlen);
}

