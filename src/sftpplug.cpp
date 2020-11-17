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

#define defininame "sftpplug.ini"
#define templatefile "sftpplug.tpl"
char inifilename[MAX_PATH] = defininame;
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


BOOL APIENTRY DllMain( HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        hinst = (HINSTANCE)hModule;
        LoadStringA(hinst, IDS_F7NEW, s_f7newconnection, countof(s_f7newconnection)-1);
        awlcopy(s_f7newconnectionW, s_f7newconnection, countof(s_f7newconnectionW)-1);
        LoadStringA(hinst, IDS_QUICKCONNECT, s_quickconnect, countof(s_quickconnect)-1);
        awlcopy(s_quickconnectW, s_quickconnect, countof(s_quickconnectW)-1);
    }
    if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        /* nothing */
    }
    return true;
}

/* FIXME: replace returnrd type to enum FS_TASK_CONTINUE / FS_TASK_ABORTED */
static bool MessageLoop(SERVERID serverid) noexcept
{
    bool aborted = false;
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (ConnectSettings && ProgressProc && get_ticks_between(ConnectSettings->lastpercenttime) > 250) {   /* FIXME: magic number! */
        // important: also call AFTER soft_aborted is true!!!
        aborted = (0 != ProgressProc(PluginNumber,  NULL,  NULL,  ConnectSettings->lastpercent));
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


static int _FsInit(int PluginNr)
{
    PluginNumber = PluginNr;
    mainthreadid = GetCurrentThreadId();
    InitMultiServer();
    return 0;
}

int WINAPI FsInit(int PluginNr, tProgressProc pProgressProc, tLogProc pLogProc, tRequestProc pRequestProc)
{
    ProgressProc = pProgressProc;
    LogProc = pLogProc;
    RequestProc = pRequestProc;
    return _FsInit(PluginNr);
}

int WINAPI FsInitW(int PluginNr, tProgressProcW pProgressProcW, tLogProcW pLogProcW, tRequestProcW pRequestProcW)
{
    ProgressProcW = pProgressProcW;
    LogProcW = pLogProcW;
    RequestProcW = pRequestProcW;
    return _FsInit(PluginNr);
}

void WINAPI FsSetCryptCallback(tCryptProc pCryptProc, int CryptoNr, int Flags)
{
    CryptProc = pCryptProc;
    CryptCheckPass = (Flags & FS_CRYPTOPT_MASTERPASS_SET) != 0;
    CryptoNumber = CryptoNr;
}

typedef struct {
    LPVOID       sftpdataptr;    /* LIBSSH2_SFTP_HANDLE or SCP_DATA */
    SERVERID     serverid;
    SERVERHANDLE rootfindhandle;
    bool         rootfindfirst;
} tLastFindStuct, *pLastFindStuct;

BOOL WINAPI FsDisconnect(LPCSTR DisconnectRoot)
{
    char DisplayName[wdirtypemax];
    GetDisplayNameFromPath(DisconnectRoot, DisplayName, countof(DisplayName)-1);
    SERVERID serverid = GetServerIdFromName(DisplayName, GetCurrentThreadId());
    if (serverid) {
        char connbuf[wdirtypemax];
        strlcpy(connbuf, "DISCONNECT \\", countof(connbuf)-1);
        strlcat(connbuf, DisplayName, countof(connbuf)-1);
        LogProc(PluginNumber, MSGTYPE_DISCONNECT, connbuf);
        SftpCloseConnection(serverid);
        SetServerIdForName(DisplayName, NULL); // this frees it too!
    }
    return true;
}
 
HANDLE WINAPI FsFindFirstW(LPCWSTR Path, LPWIN32_FIND_DATAW FindData)
{
    int hr = ERROR_SUCCESS;
    WCHAR remotedir[wdirtypemax];
    char DisplayName[wdirtypemax], PathA[wdirtypemax];
    pLastFindStuct lf;

    if (wcscmp(Path, L"\\") == 0) {  // in the root!
        char s_helptext[256];
        LoadString(hinst, IDS_HELPTEXT, s_helptext, countof(s_helptext));
        LoadServersFromIni(inifilename, s_quickconnect);
        memset(FindData, 0, sizeof(WIN32_FIND_DATAW));

        awlcopy(FindData->cFileName, s_f7newconnection, countof(FindData->cFileName)-1);
        FindData->dwFileAttributes = 0;
        SetInt64ToFileTime(&FindData->ftLastWriteTime, FS_TIME_UNKNOWN);
        FindData->nFileSizeLow = (DWORD)strlen(s_helptext);
        lf = (pLastFindStuct)malloc(sizeof(tLastFindStuct));   /* FIXME: check for NULL */
        memset(lf, 0, sizeof(tLastFindStuct));
        lf->rootfindfirst = true;
        return lf;
    }

    SERVERID serverid = NULL;
    SERVERID new_serverid = NULL;
    LPVOID sftpdataptr = NULL;

    // load server list if user connects directly via URL
    LoadServersFromIni(inifilename, s_quickconnect);
    // only disable the reading within a server!
    if (disablereading && IsMainThread()) {
        SetLastError(ERROR_NO_MORE_FILES);
        return INVALID_HANDLE_VALUE;
    }
    walcopy(PathA, Path, wdirtypemax-1);
    GetDisplayNameFromPath(PathA, DisplayName, countof(DisplayName)-1);
    serverid = GetServerIdFromName(DisplayName, GetCurrentThreadId());
    bool wasconnected = serverid ? true : false;
    if (serverid == NULL) {
        new_serverid = SftpConnectToServer(DisplayName, inifilename, NULL);
        if (!new_serverid) {
            SetLastError(ERROR_PATH_NOT_FOUND);
            return INVALID_HANDLE_VALUE;
        }
        serverid = new_serverid;
        SetServerIdForName(DisplayName, serverid);
    }
    // we are connected to server DisplayName now!

    memset(FindData, 0, sizeof(WIN32_FIND_DATAW));

    GetServerIdAndRelativePathFromPathW(Path, remotedir, wdirtypemax-1);

    // Retrieve the directory
    bool ok = (SFTP_OK == SftpFindFirstFileW(serverid, remotedir, &sftpdataptr));
        
    if (wcslen(remotedir) <= 1 || wcscmp(remotedir + 1, L"home") == 0) {    // root -> add ~ link to home dir
        SYSTEMTIME st;
        wcslcpy(FindData->cFileName, L"~", countof(FindData->cFileName)-1);
        GetSystemTime(&st);
        SystemTimeToFileTime(&st, &FindData->ftLastWriteTime);
        FindData->dwFileAttributes = FS_ATTR_UNIXMODE;
        FindData->dwReserved0 = LIBSSH2_SFTP_S_IFLNK | 0555; // attributes and format mask  /* FIXME: magic number! */

        lf = (pLastFindStuct)malloc(sizeof(tLastFindStuct));    /* FIXME: check for NULL */
        memset(lf, 0, sizeof(tLastFindStuct));
        if (ok)
            lf->sftpdataptr = sftpdataptr;
        lf->serverid = serverid;
        return (HANDLE)lf;
    }
    if (!ok) {
        if (!wasconnected) {  // initial connect failed
            SftpCloseConnection(serverid);
            SetServerIdForName(DisplayName, NULL); // this frees it too!
            freportconnect = false;
        }
        SetLastError(ERROR_PATH_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }

    if (SFTP_OK == SftpFindNextFileW(serverid, sftpdataptr, FindData)) {
        lf = (pLastFindStuct)malloc(sizeof(tLastFindStuct));    /* FIXME: check for NULL */
        memset(lf, 0, sizeof(tLastFindStuct));
        lf->sftpdataptr = sftpdataptr;
        lf->serverid = serverid;
        return (HANDLE)lf;
    }
    SftpFindClose(serverid, sftpdataptr);
    SetLastError(ERROR_NO_MORE_FILES);
    return INVALID_HANDLE_VALUE;
}

HANDLE WINAPI FsFindFirst(LPCSTR Path, LPWIN32_FIND_DATA FindData)
{
    WIN32_FIND_DATAW FindDataW;
    WCHAR PathW[wdirtypemax];
    HANDLE retval = FsFindFirstW(awfilenamecopy(PathW, Path), &FindDataW);
    if (retval != INVALID_HANDLE_VALUE)
        copyfinddatawa(FindData, &FindDataW);
    return retval;
}

BOOL WINAPI FsFindNextW(HANDLE Hdl, LPWIN32_FIND_DATAW FindData)
{
    pLastFindStuct lf;
    char name[wdirtypemax];

    if (Hdl == (HANDLE)1)    /* FIXME: need explanatory comment */
        return false;

    lf = (pLastFindStuct)Hdl;
    if (!lf || lf == INVALID_HANDLE_VALUE)
        return false;

    if (lf->rootfindfirst) {
        name[0] = 0;
        SERVERHANDLE hdl = FindFirstServer(name, countof(name)-1);
        if (!hdl)
            return false;
        awlcopy(FindData->cFileName, name, countof(FindData->cFileName)-1);
        lf->rootfindhandle = hdl;
        lf->rootfindfirst = false;
        SetInt64ToFileTime(&FindData->ftLastWriteTime, FS_TIME_UNKNOWN);
        FindData->dwFileAttributes = FS_ATTR_UNIXMODE;
        FindData->dwReserved0 = LIBSSH2_SFTP_S_IFLNK; // it's a link
        FindData->nFileSizeLow = 0;
        return true;
    }
    if (lf->rootfindhandle) {
        name[0] = 0;
        lf->rootfindhandle = FindNextServer(lf->rootfindhandle, name, countof(name)-1);
        if (!lf->rootfindhandle)
            return false;
        awlcopy(FindData->cFileName, name, countof(FindData->cFileName)-1);
        FindData->dwFileAttributes = FS_ATTR_UNIXMODE;
        FindData->dwReserved0 = LIBSSH2_SFTP_S_IFLNK; //it's a link
        return true;
    }
    if (lf->sftpdataptr) {
        int rc = SftpFindNextFileW(lf->serverid, lf->sftpdataptr, FindData);
        return (rc == SFTP_OK) ? true : false;
    }
    return false;
}

BOOL WINAPI FsFindNext(HANDLE Hdl, LPWIN32_FIND_DATA FindData)
{
    WIN32_FIND_DATAW FindDataW;
    copyfinddataaw(&FindDataW, FindData);
    BOOL retval = FsFindNextW(Hdl, &FindDataW);
    if (retval)
        copyfinddatawa(FindData, &FindDataW);
    return retval;
}

int WINAPI FsFindClose(HANDLE Hdl)
{
    if (!Hdl || Hdl == INVALID_HANDLE_VALUE)
        return 0;
    pLastFindStuct lf = (pLastFindStuct)Hdl;
    if (lf->sftpdataptr) {
        SftpFindClose(lf->serverid, lf->sftpdataptr);
        lf->sftpdataptr = NULL;
    }
    free(lf);
    return 0;
}

BOOL WINAPI FsMkDirW(LPCWSTR Path)
{
    LPCWSTR p = wcschr(Path + 1, '\\');
    if (p) {
        WCHAR remotedir[wdirtypemax];
        SERVERID serverid = GetServerIdAndRelativePathFromPathW(Path, remotedir, countof(remotedir)-1);
        if (!serverid)
            return false;
        int rc = SftpCreateDirectoryW(serverid, remotedir);
        return (rc == SFTP_OK) ? true : false;
    }
    // new connection
    char remotedir[wdirtypemax];
    walcopy(remotedir, Path + 1, countof(remotedir)-1);
    if (strcmp(remotedir, s_quickconnect) != 0 && strcmp(remotedir, s_f7newconnection) != 0) {
        LoadServersFromIni(inifilename, s_quickconnect);
        if (SftpConfigureServer(remotedir, inifilename)) {
            LoadServersFromIni(inifilename, s_quickconnect);
            return true;
        }
    }
    return false;
}

BOOL WINAPI FsMkDir(LPCSTR Path)
{
    WCHAR wbuf[wdirtypemax];
    return FsMkDirW(awfilenamecopy(wbuf, Path));
}

int WINAPI FsExecuteFileW(HWND MainWin, LPWSTR RemoteName, LPCWSTR Verb)
{
    char remoteserver[wdirtypemax];
    WCHAR remotedir[wdirtypemax];
    if (_wcsicmp(Verb, L"open") == 0) {   // follow symlink
        if (is_full_name(RemoteName)) {
            SERVERID serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir, countof(remotedir)-1);
            if (!serverid)
                return FS_EXEC_YOURSELF;
            if (!SftpLinkFolderTargetW(serverid, remotedir, wdirtypemax - 1))
                return FS_EXEC_YOURSELF;
            // now build the target name: server name followed by new path
            LPWSTR p = cut_srv_name(RemoteName);
            if (!p)
                return FS_EXEC_ERROR;
            // make sure that we can reach the path!!!
            wcslcat(RemoteName, remotedir, wdirtypemax-1);
            ReplaceSlashByBackslashW(RemoteName);
            return FS_EXEC_SYMLINK;
        }
        if (_wcsicmp(RemoteName + 1, s_f7newconnectionW) != 0) {
            LPWSTR p = RemoteName + wcslen(RemoteName);
            int pmaxlen = wdirtypemax - (size_t)(p - RemoteName) - 1;
            walcopy(remoteserver, RemoteName + 1, countof(remoteserver)-1);
            SERVERID serverid = GetServerIdFromName(remoteserver, GetCurrentThreadId());
            if (serverid) {
                SftpGetLastActivePathW(serverid, p, pmaxlen);
            } else {
                // Quick connect: We must connect here,  otherwise we
                // cannot switch to the subpath chosen by the user!
                walcopy(remoteserver, RemoteName + 1, countof(remoteserver)-1);
                if (_stricmp(remoteserver, s_quickconnect) == 0) {
                    serverid = SftpConnectToServer(remoteserver, inifilename, NULL);
                    if (!serverid)
                        return FS_EXEC_ERROR;
                    SetServerIdForName(remoteserver, serverid);
                    SftpGetLastActivePathW(serverid, p, pmaxlen);
                } else {
                    SftpGetServerBasePathW(RemoteName + 1, p, pmaxlen, inifilename);
                }
            }
            if (p[0] == 0)
                wcslcat(RemoteName, L"/", wdirtypemax-1);
            ReplaceSlashByBackslashW(RemoteName);
            return FS_EXEC_SYMLINK;
        }
        return FS_EXEC_YOURSELF;
    }
    if (_wcsicmp(Verb, L"properties") == 0) {
        if (RemoteName[1] && wcschr(RemoteName+1, '\\') == 0) {
            walcopy(remoteserver, RemoteName+1, sizeof(remoteserver)-1);
            if (_stricmp(remoteserver, s_f7newconnection) != 0 && _stricmp(remoteserver, s_quickconnect) != 0) {
                if (SftpConfigureServer(remoteserver, inifilename)) {
                    LoadServersFromIni(inifilename, s_quickconnect);
                }
            }
        } else {
            WCHAR remotenameW[wdirtypemax];
            SERVERID serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotenameW, countof(remotenameW)-1);
            /* FIXME: check serverid with NULL */
            SftpShowPropertiesW(serverid, remotenameW);
        }
        return FS_EXEC_OK;
    }
    if (_wcsnicmp(Verb, L"chmod ", 6) == 0) {
        if (RemoteName[1] && wcschr(RemoteName+1, '\\') != 0) {
            SERVERID serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir, countof(remotedir)-1);
            /* FIXME: check serverid with NULL */
            if (SftpChmodW(serverid, remotedir, Verb+6))
                return FS_EXEC_OK;
        }
        return FS_EXEC_ERROR;
    }
    if (_wcsnicmp(Verb, L"quote ", 6) == 0) {
        if (wcsncmp(Verb+6, L"cd ", 3) == 0) {
            // first get the start path within the plugin
            SERVERID serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir, countof(remotedir)-1);
            /* FIXME: check serverid with NULL */
            if (Verb[9] != '\\' && Verb[9] != '/') {     // relative path?
                wcslcatbackslash(remotedir, countof(remotedir)-1);
                wcslcat(remotedir, Verb+9, countof(remotedir)-1);
            } else
                wcslcpy(remotedir, Verb+9, countof(remotedir)-1);
            ReplaceSlashByBackslashW(remotedir);

            LPWSTR p = cut_srv_name(RemoteName);
            if (!p)
                return FS_EXEC_ERROR;
            // make sure that we can reach the path!!!
            wcslcat(RemoteName, remotedir, wdirtypemax-1);
            ReplaceSlashByBackslashW(RemoteName);
            return FS_EXEC_SYMLINK;
        } else {
            if (is_full_name(RemoteName)) {
                WCHAR remotedir[wdirtypemax];
                SERVERID serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir, countof(remotedir)-1);
                /* FIXME: check serverid with NULL */
                if (SftpQuoteCommand2W(serverid, remotedir, Verb+6, NULL, 0) != 0)  /* FIXME: this function returned -1, 0, 1 */
                    return FS_EXEC_OK;
            }
        }
        return FS_EXEC_ERROR;
    }
    if (_wcsnicmp(Verb, L"mode ", 5) == 0) {   // Binary/Text/Auto
        SftpSetTransferModeW(Verb+5);
        /* FIXME: return FS_EXEC_OK ??? */
    }
    return FS_EXEC_ERROR;
}

int WINAPI FsExecuteFile(HWND MainWin, LPSTR RemoteName, LPCSTR Verb)
{
    WCHAR RemoteNameW[wdirtypemax], VerbW[wdirtypemax];
    int ret = FsExecuteFileW(MainWin, awfilenamecopy(RemoteNameW, RemoteName), awfilenamecopy(VerbW, Verb));
    if (ret == FS_EXEC_SYMLINK)
        walcopy(RemoteName, RemoteNameW, MAX_PATH-1);
    return ret;
}

static bool CopyMoveEncryptedPassword(LPCSTR OldName, LPSTR NewName, bool Move)
{
    if (!CryptProc)
        return false;
    int mode = Move ? FS_CRYPT_MOVE_PASSWORD : FS_CRYPT_COPY_PASSWORD;
    int rc = CryptProc(PluginNumber, CryptoNumber, mode, OldName, NewName, 0);
    return (rc == FS_FILE_OK) ? true : false;
}

int WINAPI FsRenMovFileW(LPCWSTR OldName, LPCWSTR NewName, BOOL Move, BOOL OverWrite, RemoteInfoStruct * ri)
{
    WCHAR olddir[wdirtypemax], newdir[wdirtypemax];

    // Rename or copy a server?
    LPCWSTR p1 = wcschr(OldName + 1, '\\');
    LPCWSTR p2 = wcschr(NewName + 1, '\\');
    if (p1 == NULL && p2 == NULL) {
        char OldNameA[MAX_PATH], NewNameA[MAX_PATH];
        walcopy(OldNameA, OldName + 1, countof(OldNameA)-1);
        walcopy(NewNameA, NewName + 1, countof(NewNameA)-1);
        int rc = CopyMoveServerInIni(OldNameA, NewNameA, !!Move, !!OverWrite, inifilename);
        if (rc == FS_FILE_OK) {
            CopyMoveEncryptedPassword(OldNameA, NewNameA, !!Move);
            return FS_FILE_OK;
        }
        if (rc == FS_FILE_EXISTS)
            return FS_FILE_EXISTS;
        return FS_FILE_NOTFOUND;
    }

    pConnectSettings serverid1 = GetServerIdAndRelativePathFromPathW(OldName, olddir, countof(olddir)-1);
    pConnectSettings serverid2 = GetServerIdAndRelativePathFromPathW(NewName, newdir, countof(newdir)-1);

    // must be on same server!
    if (serverid1 != serverid2 || serverid1 == NULL)
        return FS_FILE_NOTFOUND;

    ResetLastPercent(serverid1);
    
    bool isdir = (ri->Attr & FILE_ATTRIBUTE_DIRECTORY) ? true : false;

    int rc = SftpRenameMoveFileW(serverid1, olddir, newdir, !!Move, !!OverWrite, isdir);
    switch (rc) {
    case SFTP_OK:
        return FS_FILE_OK;
    case SFTP_EXISTS:
        return FS_FILE_EXISTS;
    }
    return FS_FILE_NOTFOUND;
}

int WINAPI FsRenMovFile(LPCSTR OldName, LPCSTR NewName, BOOL Move, BOOL OverWrite, RemoteInfoStruct * ri)
{
    WCHAR OldNameW[wdirtypemax], NewNameW[wdirtypemax];
    return FsRenMovFileW(awfilenamecopy(OldNameW, OldName), awfilenamecopy(NewNameW, NewName), Move, OverWrite, ri);
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

int WINAPI FsGetFileW(LPCWSTR RemoteName, LPWSTR LocalName, int CopyFlags, RemoteInfoStruct * ri)
{
    bool OverWrite = !!(CopyFlags & FS_COPYFLAGS_OVERWRITE);
    bool Resume = !!(CopyFlags & FS_COPYFLAGS_RESUME);
    bool Move = !!(CopyFlags & FS_COPYFLAGS_MOVE);

    if (wcslen(RemoteName) < 3)
        return FS_FILE_NOTFOUND;

    if (wcscmp(RemoteName + 1, s_f7newconnectionW) == 0) {
        DWORD dwAccess = GENERIC_WRITE;
        DWORD dwShareMode = FILE_SHARE_READ | FILE_SHARE_WRITE;
        DWORD dwDispos = OverWrite ? CREATE_ALWAYS : CREATE_NEW;
        DWORD dwFlags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN;
        HANDLE houtfile = CreateFileT(LocalName, dwAccess, dwShareMode, NULL, dwDispos, dwFlags, NULL);
        if (!houtfile || houtfile == INVALID_HANDLE_VALUE)
            return OverWrite ? FS_FILE_EXISTS : FS_FILE_WRITEERROR;
        DWORD written;
        char s_helptext[256];
        LoadString(hinst, IDS_HELPTEXT, s_helptext, countof(s_helptext));
        BOOL ret = WriteFile(houtfile, s_helptext, (DWORD)strlen(s_helptext), &written, NULL);
        CloseHandle(houtfile);
        return ret ? FS_FILE_OK : FS_FILE_WRITEERROR;
    }

    LPWSTR p = wcsrchr(LocalName, '\\');
    if (p)
        RemoveInalidCharsW(p + 1);  // Changes the name passed in!

    WCHAR remotedir[wdirtypemax];
    pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir, countof(remotedir)-1);
    if (serverid == NULL)
        return FS_FILE_READERROR;
    ResetLastPercent(serverid);

    int err = ProgressProcT(PluginNumber, RemoteName, LocalName, 0);
    if (err)
        return FS_FILE_USERABORT;
    if (!OverWrite && !Resume && FileExistsT(LocalName)) {
        // Resume isn't possible because we cannot know
        // which <CR> characters were already in the original
        // file,  and which were added during the download
        bool TextMode = (serverid->unixlinebreaks == 1) && SftpDetermineTransferModeW(RemoteName);
        if (TextMode)
            return SFTP_FAILED;
        return FS_FILE_EXISTSRESUMEALLOWED;
    }
    if (OverWrite) {
        DeleteFileT(LocalName);
    }

    while (true) {  // auto-resume loop
        int rc = SftpDownloadFileW(serverid, remotedir, LocalName, true, ri->Size64, &ri->LastWriteTime, Resume);
        switch (rc) {
            case SFTP_OK:          return FS_FILE_OK;
            case SFTP_EXISTS:      return FS_FILE_EXISTS;
            case SFTP_READFAILED:  return FS_FILE_READERROR;
            case SFTP_WRITEFAILED: return FS_FILE_WRITEERROR;
            case SFTP_ABORT:       return FS_FILE_USERABORT;
            case SFTP_PARTIAL:     Resume = true; break;
            default: return FS_FILE_OK;
        }
    }
    return FS_FILE_OK;
}

int WINAPI FsGetFile(LPCSTR RemoteName, LPSTR LocalName, int CopyFlags, RemoteInfoStruct* ri)
{
    WCHAR RemoteNameW[wdirtypemax], LocalNameW[wdirtypemax];
    return FsGetFileW(awfilenamecopy(RemoteNameW, RemoteName), awfilenamecopy(LocalNameW, LocalName), CopyFlags, ri);
}

int WINAPI FsPutFileW(LPCWSTR LocalName, LPCWSTR RemoteName, int CopyFlags)
{
    bool OverWrite = !!(CopyFlags & FS_COPYFLAGS_OVERWRITE);
    bool Resume = !!(CopyFlags & FS_COPYFLAGS_RESUME);
    bool Move = !!(CopyFlags & FS_COPYFLAGS_MOVE);

    // Auto-overwrites files -> return error if file exists
    if (CopyFlags & (FS_COPYFLAGS_EXISTS_SAMECASE | FS_COPYFLAGS_EXISTS_DIFFERENTCASE))
        if (!OverWrite && !Resume)
            return FS_FILE_EXISTSRESUMEALLOWED;

    if (wcslen(RemoteName) < 3)
        return FS_FILE_WRITEERROR;

    int err = ProgressProcT(PluginNumber, LocalName, RemoteName, 0);
    if (err)
        return FS_FILE_USERABORT;

    WCHAR remotedir[wdirtypemax];
    
    pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir, countof(remotedir)-1);
    if (serverid == NULL)
        return FS_FILE_READERROR;
    ResetLastPercent(serverid);

    bool setattr = !!(CopyFlags & FS_COPYFLAGS_EXISTS_SAMECASE);
    int rc = SftpUploadFileW(serverid, LocalName, remotedir, Resume, setattr);
    switch (rc) {
        case SFTP_OK:          return FS_FILE_OK;
        case SFTP_EXISTS:      return SftpSupportsResume(serverid) ? FS_FILE_EXISTSRESUMEALLOWED : FS_FILE_EXISTS;
        case SFTP_READFAILED:  return FS_FILE_READERROR;
        case SFTP_WRITEFAILED: return FS_FILE_WRITEERROR;
        case SFTP_ABORT:       return FS_FILE_USERABORT;
    }
    return FS_FILE_NOTFOUND;
}

int WINAPI FsPutFile(LPCSTR LocalName, LPCSTR RemoteName, int CopyFlags)
{
    WCHAR LocalNameW[wdirtypemax], RemoteNameW[wdirtypemax];
    return FsPutFileW(awfilenamecopy(LocalNameW, LocalName), awfilenamecopy(RemoteNameW, RemoteName), CopyFlags);
}

BOOL WINAPI FsDeleteFileW(LPCWSTR RemoteName)
{
    if (wcslen(RemoteName) < 3)
        return false;

    LPCWSTR p = wcschr(RemoteName+1, '\\');
    if (p) {
        WCHAR remotedir[wdirtypemax];
        pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir, countof(remotedir)-1);
        if (serverid == NULL)
            return false;
        ResetLastPercent(serverid);
        int rc = SftpDeleteFileW(serverid, remotedir, false);
        return (rc == SFTP_OK) ? true : false;
    }
    // delete server
    char remotedir[wdirtypemax];
    walcopy(remotedir, RemoteName+1, sizeof(remotedir)-1);
    if (_stricmp(remotedir, s_f7newconnection) != 0 && _stricmp(remotedir, s_quickconnect) != 0) {
        if (DeleteServerFromIni(remotedir, inifilename)) {
            if (CryptProc)
                CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_DELETE_PASSWORD, remotedir, NULL, 0);
            return true;
        }
    }
    return false;
}

BOOL WINAPI FsDeleteFile(LPCSTR RemoteName)
{
    WCHAR RemoteNameW[wdirtypemax];
    return FsDeleteFileW(awfilenamecopy(RemoteNameW, RemoteName));
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

void WINAPI FsGetDefRootName(LPSTR DefRootName, int maxlen)
{
    strlcpy(DefRootName, defrootname, maxlen);
}

// use default location,  but our own ini file name!
void WINAPI FsSetDefaultParams(FsDefaultParamStruct * dps)
{
    strlcpy(inifilename, dps->DefaultIniName, MAX_PATH-1);
    LPSTR p = strrchr(inifilename, '\\');
    if (p)
        p[1] = 0;
    else
        inifilename[0] = 0;
    strlcat(inifilename, defininame, countof(inifilename)-1);

    // copy ini template from plugin dir to ini location if it exists!
    char templatename[MAX_PATH];
    DWORD len = GetModuleFileName(hinst, templatename, countof(templatename)-1);
    if (len > 0) {
        LPSTR p = strrchr(templatename, '\\');
        if (p) {
            p[1] = 0;
            strlcat(templatename, templatefile, countof(templatename)-1);
        }
        CopyFileA(templatename, inifilename, true);  // only copy if target doesn't exist
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

int WINAPI FsGetBackgroundFlags(void)
{
    return BG_DOWNLOAD | BG_UPLOAD | BG_ASK_USER;
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

