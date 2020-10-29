// sertransplg.cpp : Defines the entry point for the DLL application.
//

#include <windows.h>
#include <stdlib.h>
#include "fsplugin.h"
#include "utils.h"
#include "res/resource.h"
#include "sftpfunc.h"
#include "multiserver.h"
#include "cunicode.h"

HINSTANCE hinst;
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

BOOL disablereading = false;   // disable reading of subdirs to delete whole drives
BOOL freportconnect = true;    // report connect to caller only on first connect
BOOL CryptCheckPass = false;   // check 'store password encrypted' by default

BOOL APIENTRY DllMain( HANDLE hModule,  
                       DWORD  ul_reason_for_call,  
                       LPVOID lpReserved
                )
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        hinst = (HINSTANCE)hModule;
        LoadString(hinst,  IDS_F7NEW,  s_f7newconnection,  sizeof(s_f7newconnection)-1);
        awlcopy(s_f7newconnectionW,  s_f7newconnection,  countof(s_f7newconnectionW)-1);
        LoadString(hinst,  IDS_QUICKCONNECT,  s_quickconnect,  sizeof(s_quickconnect)-1);
        awlcopy(s_quickconnectW,  s_quickconnect,  countof(s_quickconnectW)-1);
    } else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
    }
    return TRUE;
}

int PluginNumber = 0;
int CryptoNumber = 0;
DWORD mainthreadid = 0;
tProgressProc ProgressProc = NULL;
tProgressProcW ProgressProcW = NULL;
tLogProc LogProc = NULL;
tLogProcW LogProcW = NULL;
tRequestProc RequestProc = NULL;
tRequestProcW RequestProcW = NULL;
tCryptProc CryptProc = NULL;

BOOL IsMainThread()
{
    return GetCurrentThreadId() == mainthreadid;
}

BOOL MessageLoop(void* serverid)
{
    BOOL aborted = false;
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (ConnectSettings && ProgressProc && labs(GetCurrentTime() - ConnectSettings->lastpercenttime) > 250) {
        // important: also call AFTER soft_aborted is true!!!
        aborted = (0 != ProgressProc(PluginNumber,  NULL,  NULL,  ConnectSettings->lastpercent));
        // allow abort with Escape when there is no progress dialog!
        ConnectSettings->lastpercenttime = GetCurrentTime();
    }
    return aborted;
}

void ShowStatus(char* status)
{
    if (LogProc)
        LogProc(PluginNumber, MSGTYPE_DETAILS, status);
}

void ShowStatusW(WCHAR* status)
{
    LogProcT(PluginNumber, MSGTYPE_DETAILS, status);
}

BOOL UpdatePercentBar(void* serverid,  int percent)
{
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (ConnectSettings)
        ConnectSettings->lastpercent = percent;  // used for MessageLoop below

    return MessageLoop(serverid);  // This actually sets the percent bar!
}

SERVERID GetServerIdAndRelativePathFromPath(char* Path, char* RelativePath, int maxlen)
{
    char DisplayName[wdirtypemax];
    GetDisplayNameFromPath(Path, DisplayName, sizeof(DisplayName)-1);
    SERVERID serverid = GetServerIdFromName(DisplayName, GetCurrentThreadId());
    if (serverid) {
        RelativePath[0] = 0;
        char* p = Path;
        while (p[0] == '\\' || p[0] == '/')  // skip initial slash
            p++;
        while (p[0] != 0 && p[0] != '\\' && p[0] != '/') // skip path
            p++;
        strlcat(RelativePath, p, maxlen);
        if (RelativePath[0] == 0)
            strlcpy(RelativePath, "\\", maxlen-1);
    } else if (maxlen)
        strlcpy(RelativePath, "\\", maxlen-1);
    return serverid;
}

SERVERID GetServerIdAndRelativePathFromPathW(WCHAR* Path, WCHAR* RelativePath, int maxlen)
{
    char DisplayName[wdirtypemax], PathA[wdirtypemax];
    walcopy(PathA, Path, sizeof(PathA)-1);
    GetDisplayNameFromPath(PathA, DisplayName, sizeof(DisplayName)-1);
    SERVERID serverid = GetServerIdFromName(DisplayName, GetCurrentThreadId());
    if (serverid) {
        RelativePath[0] = 0;
        WCHAR* p = Path;
        while (p[0] == '\\' || p[0] == '/')  // skip initial slash
            p++;
        while (p[0] != 0 && p[0] != '\\' && p[0] != '/') // skip path
            p++;
        wcslcat(RelativePath, p, maxlen);
        if (RelativePath[0] == 0)
            wcslcpy(RelativePath, L"\\", maxlen-1);
    } else if (maxlen)
        wcslcpy(RelativePath, L"\\", maxlen-1);
    return serverid;
}

int WINAPI FsInit(int PluginNr, tProgressProc pProgressProc, tLogProc pLogProc, tRequestProc pRequestProc)
{
    ProgressProc = pProgressProc;
    LogProc = pLogProc;
    RequestProc = pRequestProc;
    PluginNumber = PluginNr;
    mainthreadid = GetCurrentThreadId();
    InitMultiServer();
    return 0;
}

int WINAPI FsInitW(int PluginNr, tProgressProcW pProgressProcW, tLogProcW pLogProcW, tRequestProcW pRequestProcW)
{
    ProgressProcW = pProgressProcW;
    LogProcW = pLogProcW;
    RequestProcW = pRequestProcW;
    PluginNumber = PluginNr;
    mainthreadid = GetCurrentThreadId();
    InitMultiServer();
    return 0;
}

void WINAPI FsSetCryptCallback(tCryptProc pCryptProc, int CryptoNr, int Flags)
{
    CryptProc = pCryptProc;
    CryptCheckPass = (Flags & FS_CRYPTOPT_MASTERPASS_SET) != 0;
    CryptoNumber = CryptoNr;
}

typedef struct {
    void* sftpdataptr;
    SERVERID serverid;
    SERVERHANDLE rootfindhandle;
    BOOL rootfindfirst;
} tLastFindStuct, *pLastFindStuct;

BOOL WINAPI FsDisconnect(char* DisconnectRoot)
{
    char DisplayName[wdirtypemax];
    GetDisplayNameFromPath(DisconnectRoot, DisplayName, sizeof(DisplayName)-1);
    SERVERID serverid = GetServerIdFromName(DisplayName, GetCurrentThreadId());
    if (serverid) {
        char connbuf[wdirtypemax];
        strlcpy(connbuf, "DISCONNECT \\", sizeof(connbuf)-1);
        strlcat(connbuf, DisplayName, sizeof(connbuf)-1);
        LogProc(PluginNumber, MSGTYPE_DISCONNECT, connbuf);
        SftpCloseConnection(serverid);
        SetServerIdForName(DisplayName, NULL); // this frees it too!
    }
    return TRUE;
}
 
HANDLE WINAPI FsFindFirstW(WCHAR* Path, WIN32_FIND_DATAW *FindData)
{
    WCHAR remotedir[wdirtypemax];
    char DisplayName[wdirtypemax], PathA[wdirtypemax];
    pLastFindStuct lf;

    void* sftpdataptr = NULL;
    BOOL wasconnected = true;

    if (wcscmp(Path, L"\\") == 0) {  // in the root!
        char s_helptext[256];
        LoadString(hinst, IDS_HELPTEXT, s_helptext, sizeof(s_helptext));
        LoadServersFromIni(inifilename, s_quickconnect);
        memset(FindData, 0, sizeof(WIN32_FIND_DATA));

        awlcopy(FindData->cFileName, s_f7newconnection, countof(FindData->cFileName)-1);
        FindData->dwFileAttributes = 0;
        FindData->ftLastWriteTime.dwHighDateTime = 0xFFFFFFFF;
        FindData->ftLastWriteTime.dwLowDateTime  = 0xFFFFFFFE;
        FindData->nFileSizeLow = (DWORD)strlen(s_helptext);
        lf = (pLastFindStuct)malloc(sizeof(tLastFindStuct));
        memset(lf, 0, sizeof(tLastFindStuct));
        lf->rootfindfirst = true;
        return lf;
    } else {
        // load server list if user connects directly via URL
        LoadServersFromIni(inifilename, s_quickconnect);
        // only disable the reading within a server!
        if (disablereading && IsMainThread()) {
            SetLastError(ERROR_NO_MORE_FILES);
            return INVALID_HANDLE_VALUE;
        }

        walcopy(PathA, Path, wdirtypemax-1);
        GetDisplayNameFromPath(PathA, DisplayName, sizeof(DisplayName)-1);
        SERVERID serverid = GetServerIdFromName(DisplayName, GetCurrentThreadId());
        if (serverid == NULL) {
            wasconnected = false;
            serverid = SftpConnectToServer(DisplayName, inifilename, NULL);
            if (serverid)
                SetServerIdForName(DisplayName, serverid);
            else {
                SetLastError(ERROR_PATH_NOT_FOUND);
                return INVALID_HANDLE_VALUE;
            }
        }
        // we are connected to server DisplayName now!

        memset(FindData, 0, sizeof(WIN32_FIND_DATAW));

        GetServerIdAndRelativePathFromPathW(Path, remotedir, wdirtypemax-1);

        // Retrieve the directory
        BOOL ok = (SFTP_OK == SftpFindFirstFileW(serverid, remotedir, &sftpdataptr));
        
        if (wcslen(remotedir) <= 1 || wcscmp(remotedir+1, L"home") == 0) {    // root -> add ~ link to home dir
            SYSTEMTIME st;
            FindData->dwFileAttributes = 0;
            wcslcpy(FindData->cFileName, L"~", countof(FindData->cFileName)-1);
            FindData->cAlternateFileName[0] = 0;
            FindData->ftCreationTime.dwHighDateTime = 0;
            FindData->ftCreationTime.dwLowDateTime = 0;
            FindData->ftLastAccessTime.dwHighDateTime = 0;
            FindData->ftLastAccessTime.dwLowDateTime = 0;
            GetSystemTime(&st);
            SystemTimeToFileTime(&st, &FindData->ftLastWriteTime);
            FindData->nFileSizeHigh = 0;
            FindData->nFileSizeLow = 0;
            FindData->dwFileAttributes |= 0x80000000;
            FindData->dwReserved0 = LIBSSH2_SFTP_S_IFLNK | 0555; //attributes and format mask

            lf = (pLastFindStuct)malloc(sizeof(tLastFindStuct));
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
            lf = (pLastFindStuct)malloc(sizeof(tLastFindStuct));
            memset(lf, 0, sizeof(tLastFindStuct));
            lf->sftpdataptr = sftpdataptr;
            lf->serverid = serverid;
            return (HANDLE)lf;
        } else {
            SftpFindClose(serverid, sftpdataptr);
            SetLastError(ERROR_NO_MORE_FILES);
            return INVALID_HANDLE_VALUE;
        }
    }
    return INVALID_HANDLE_VALUE;
}

HANDLE WINAPI FsFindFirst(char* Path, WIN32_FIND_DATA *FindData)
{
    WIN32_FIND_DATAW FindDataW;
    WCHAR PathW[wdirtypemax];
    HANDLE retval = FsFindFirstW(awfilenamecopy(PathW, Path), &FindDataW);
    if (retval != INVALID_HANDLE_VALUE)
        copyfinddatawa(FindData, &FindDataW);
    return retval;
}

BOOL WINAPI FsFindNextW(HANDLE Hdl, WIN32_FIND_DATAW *FindData)
{
    pLastFindStuct lf;
    char name[wdirtypemax];

    if (Hdl == (HANDLE)1)
        return false;

    lf = (pLastFindStuct)Hdl;
    if (lf != INVALID_HANDLE_VALUE) {
        if (lf->rootfindfirst) {
            name[0] = 0;
            SERVERHANDLE hdl = FindFirstServer(name, sizeof(name)-1);
            if (hdl) {
                awlcopy(FindData->cFileName, name, countof(FindData->cFileName)-1);
                lf->rootfindhandle = hdl;
                lf->rootfindfirst = false;
                FindData->dwFileAttributes = 0x80000000;
                FindData->dwReserved0 = LIBSSH2_SFTP_S_IFLNK; //it's a link
                FindData->ftLastWriteTime.dwHighDateTime = 0xFFFFFFFF;
                FindData->ftLastWriteTime.dwLowDateTime  = 0xFFFFFFFE;
                FindData->nFileSizeLow = 0;
                return true;
            } else
                return false;
        } else if (lf->rootfindhandle) {
            name[0] = 0;
            lf->rootfindhandle = FindNextServer(lf->rootfindhandle, name, sizeof(name)-1);
            if (lf->rootfindhandle) {
                awlcopy(FindData->cFileName, name, countof(FindData->cFileName)-1);
                FindData->dwFileAttributes = 0x80000000;
                FindData->dwReserved0 = LIBSSH2_SFTP_S_IFLNK; //it's a link
            }
            return lf->rootfindhandle != NULL;
        } else if (lf->sftpdataptr)
            return SftpFindNextFileW(lf->serverid, lf->sftpdataptr, FindData) == SFTP_OK;
    }
    return false;
}

BOOL WINAPI FsFindNext(HANDLE Hdl, WIN32_FIND_DATA *FindData)
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
    if (Hdl == INVALID_HANDLE_VALUE)
        return 0;
    pLastFindStuct lf;
    lf = (pLastFindStuct)Hdl;
    if (lf->sftpdataptr) {
        SftpFindClose(lf->serverid, lf->sftpdataptr);
        lf->sftpdataptr = NULL;
    }
    free(lf);
    return 0;
}

BOOL WINAPI FsMkDirW(WCHAR* Path)
{
    WCHAR* p = wcschr(Path+1, '\\');
    if (p) {
        WCHAR remotedir[wdirtypemax];
        SERVERID serverid = GetServerIdAndRelativePathFromPathW(Path, remotedir, countof(remotedir)-1);
        if (serverid)
            return SftpCreateDirectoryW(serverid, remotedir) == SFTP_OK;
        else
            return false;
    } else {  // new connection
        char remotedir[wdirtypemax];
        walcopy(remotedir, Path+1, sizeof(remotedir)-1);
        if (strcmp(remotedir, s_quickconnect) != 0 && strcmp(remotedir, s_f7newconnection) != 0) {
            LoadServersFromIni(inifilename, s_quickconnect);
            if (SftpConfigureServer(remotedir, inifilename)) {
                LoadServersFromIni(inifilename, s_quickconnect);
                return true;
            } else
                return false;
        } else
            return false;
    }
}

BOOL WINAPI FsMkDir(char* Path)
{
    WCHAR wbuf[wdirtypemax];
    return FsMkDirW(awfilenamecopy(wbuf, Path));
}

int WINAPI FsExecuteFileW(HWND MainWin, WCHAR* RemoteName, WCHAR* Verb)
{
    char remoteserver[wdirtypemax];
    WCHAR remotedir[wdirtypemax];
    if (_wcsicmp(Verb, L"open") == 0) {   // follow symlink
        if (RemoteName[1] && wcschr(RemoteName+1, '\\') != 0) {
            SERVERID serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir, countof(remotedir)-1);
            
            if (SftpLinkFolderTargetW(serverid, remotedir, wdirtypemax-1)) {
                // now build the target name: server name followed by new path
                WCHAR* p;
                p = wcschr(RemoteName+1, '\\');
                if (p) {
                    p[0] = 0;
                    // make sure that we can reach the path!!!
                    wcslcat(RemoteName, remotedir, wdirtypemax-1);
                    ReplaceSlashByBackslashW(RemoteName);
                    return FS_EXEC_SYMLINK;
                }
                return FS_EXEC_ERROR;
            }
        } else {
            if (_wcsicmp(RemoteName+1, s_f7newconnectionW) != 0) {
                WCHAR* p = RemoteName + wcslen(RemoteName);
                walcopy(remoteserver, RemoteName+1, sizeof(remoteserver)-1);
                SERVERID serverid = GetServerIdFromName(remoteserver, GetCurrentThreadId());
                if (serverid) {
                    SftpGetLastActivePathW(serverid, p, wdirtypemax - (DWORD)(p - RemoteName) - 1);
                } else {
                    // Quick connect: We must connect here,  otherwise we
                    // cannot switch to the subpath chosen by the user!
                    walcopy(remoteserver, RemoteName+1, sizeof(remoteserver)-1);
                    if (_stricmp(remoteserver, s_quickconnect) == 0) {
                        serverid = SftpConnectToServer(remoteserver, inifilename, NULL);
                        if (serverid) {
                            SetServerIdForName(remoteserver, serverid);
                            SftpGetLastActivePathW(serverid, p, wdirtypemax - (DWORD)(p - RemoteName) - 1);
                        } else
                            return FS_EXEC_ERROR;
                    } else
                        SftpGetServerBasePathW(RemoteName+1, p, wdirtypemax - (DWORD)(p - RemoteName) - 1, inifilename);
                }
                if (p[0] == 0)
                    wcslcat(RemoteName, L"/", wdirtypemax-1);
                ReplaceSlashByBackslashW(RemoteName);
                return FS_EXEC_SYMLINK;
            }
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
            SftpShowPropertiesW(serverid, remotenameW);
        }
        return FS_EXEC_OK;
    }
    if (_wcsnicmp(Verb, L"chmod ", 6) == 0) {
        if (RemoteName[1] && wcschr(RemoteName+1, '\\') != 0) {
            SERVERID serverid=GetServerIdAndRelativePathFromPathW(RemoteName, remotedir, countof(remotedir)-1);
            if (SftpChmodW(serverid, remotedir, Verb+6))
                return FS_EXEC_OK;
        }
        return FS_EXEC_ERROR;
    }
    if (_wcsnicmp(Verb, L"quote ", 6) == 0) {
        if (wcsncmp(Verb+6, L"cd ", 3) == 0) {
            // first get the start path within the plugin
            SERVERID serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir, countof(remotedir)-1);

            if (Verb[9] != '\\' && Verb[9] != '/') {     // relative path?
                wcslcatbackslash(remotedir, countof(remotedir)-1);
                wcslcat(remotedir, Verb+9, countof(remotedir)-1);
            } else
                wcslcpy(remotedir, Verb+9, countof(remotedir)-1);
            ReplaceSlashByBackslashW(remotedir);

            WCHAR* p;
            p = wcschr(RemoteName+1, '\\');
            if (p) {
                p[0] = 0;
                // make sure that we can reach the path!!!
                wcslcat(RemoteName, remotedir, wdirtypemax-1);
                ReplaceSlashByBackslashW(RemoteName);
                return FS_EXEC_SYMLINK;
            }
        } else {
            if (RemoteName[1] && wcschr(RemoteName+1, '\\')!=0) {
                WCHAR remotedir[wdirtypemax];
                SERVERID serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir, countof(remotedir)-1);
                if (SftpQuoteCommand2W(serverid, remotedir, Verb+6, NULL, 0))
                    return FS_EXEC_OK;
            }
        }
    }
    if (_wcsnicmp(Verb, L"mode ", 5) == 0) {   // Binary/Text/Auto
        SftpSetTransferModeW(Verb+5);
    }
    return FS_EXEC_ERROR;
}

int WINAPI FsExecuteFile(HWND MainWin, char* RemoteName, char* Verb)
{
    WCHAR RemoteNameW[wdirtypemax], VerbW[wdirtypemax];
    int ret=FsExecuteFileW(MainWin, awfilenamecopy(RemoteNameW, RemoteName), awfilenamecopy(VerbW, Verb));
    if (ret == FS_EXEC_SYMLINK)
        walcopy(RemoteName, RemoteNameW, MAX_PATH-1);
    return ret;
}

BOOL CopyMoveEncryptedPassword(char* OldName, char* NewName, BOOL Move)
{
    if (CryptProc)
        return CryptProc(PluginNumber, CryptoNumber, Move ? FS_CRYPT_MOVE_PASSWORD:FS_CRYPT_COPY_PASSWORD, 
                         OldName, NewName, 0) == FS_FILE_OK;
    return false;
}

int WINAPI FsRenMovFileW(WCHAR* OldName, WCHAR* NewName, BOOL Move, BOOL OverWrite, RemoteInfoStruct* ri)
{
    WCHAR olddir[wdirtypemax], newdir[wdirtypemax];

    // Rename or copy a server?
    WCHAR* p1 = wcschr(OldName+1, '\\');
    WCHAR* p2 = wcschr(NewName+1, '\\');
    if (p1 == NULL && p2 == NULL) {
        char OldNameA[MAX_PATH], NewNameA[MAX_PATH];
        walcopy(OldNameA, OldName+1, sizeof(OldNameA)-1);
        walcopy(NewNameA, NewName+1, sizeof(NewNameA)-1);
        switch (CopyMoveServerInIni(OldNameA, NewNameA, Move, OverWrite, inifilename)) {
        case 0:
            CopyMoveEncryptedPassword(OldNameA, NewNameA, Move);
            return FS_FILE_OK;
            break;
        case 1:
            return FS_FILE_EXISTS;
            break;
        }
        return FS_FILE_NOTFOUND;
    }

    SERVERID serverid1 = GetServerIdAndRelativePathFromPathW(OldName, olddir, countof(olddir)-1);
    SERVERID serverid2 = GetServerIdAndRelativePathFromPathW(NewName, newdir, countof(newdir)-1);

    // must be on same server!
    if (serverid1 != serverid2 || serverid1 == NULL)
        return FS_FILE_NOTFOUND;

    pConnectSettings ConnectSettings = (pConnectSettings)serverid1;
    if (ConnectSettings)
        ConnectSettings->lastpercent = 0;
    
    BOOL isdir = false;
    if (ri)
        isdir = (ri->Attr & FILE_ATTRIBUTE_DIRECTORY) != 0;

    switch (SftpRenameMoveFileW(serverid1, olddir, newdir, Move, OverWrite, isdir)) {
    case SFTP_OK:
        return FS_FILE_OK;
    case SFTP_EXISTS:
        return FS_FILE_EXISTS;
    default:
        return FS_FILE_NOTFOUND;
    }
}

int WINAPI FsRenMovFile(char* OldName, char* NewName, BOOL Move, BOOL OverWrite, RemoteInfoStruct* ri)
{
    WCHAR OldNameW[wdirtypemax], NewNameW[wdirtypemax];
    return FsRenMovFileW(awfilenamecopy(OldNameW, OldName), awfilenamecopy(NewNameW, NewName), Move, OverWrite, ri);
}

BOOL FileExistsT(WCHAR* LocalName)
{
    WIN32_FIND_DATAW s;
    HANDLE findhandle;
    findhandle = FindFirstFileT(LocalName, &s);
    if (findhandle == INVALID_HANDLE_VALUE)
        return false;
    else {
        FindClose(findhandle);
        return true;
    }
}

void RemoveInalidChars(char* p)
{
    while (p[0]) {
        if ((unsigned char)(p[0]) < 32)
            p[0] = ' ';
        else if (p[0] == ':' || p[0] == '|' || p[0] == '*' || p[0] == '?' || p[0] == '\\' || p[0] == '/' || p[0] == '"')
            p[0] = '_';
        p++;
    }
}

void RemoveInalidCharsW(WCHAR* p)
{
    while (p[0]) {
        if ((unsigned int)(p[0]) < 32)
            p[0] = ' ';
        else if (p[0] == ':' || p[0] == '|' || p[0] == '*' || p[0] == '?' || p[0] == '\\' || p[0] == '/' || p[0] == '"')
            p[0] = '_';
        p++;
    }
}

int WINAPI FsGetFileW(WCHAR* RemoteName, WCHAR* LocalName, int CopyFlags, RemoteInfoStruct* ri)
{
    int err;
    BOOL OverWrite, Resume, Move;

    OverWrite = CopyFlags & FS_COPYFLAGS_OVERWRITE;
    Resume = CopyFlags & FS_COPYFLAGS_RESUME;
    Move = CopyFlags & FS_COPYFLAGS_MOVE;

    if (wcslen(RemoteName) < 3)
        return FS_FILE_NOTFOUND;

    if (wcscmp(RemoteName+1, s_f7newconnectionW) == 0) {
        HANDLE houtfile = CreateFileT(LocalName, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, 
            OverWrite ? CREATE_ALWAYS : CREATE_NEW, 
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (houtfile != INVALID_HANDLE_VALUE) {
            DWORD written;
            char s_helptext[256];
            LoadString(hinst, IDS_HELPTEXT, s_helptext, sizeof(s_helptext));
            BOOL ret = WriteFile(houtfile, s_helptext, (DWORD)strlen(s_helptext), &written, NULL);
            CloseHandle(houtfile);
            if (ret)
                return FS_FILE_OK;
        } else
            if (OverWrite)
                return FS_FILE_EXISTS;
        return FS_FILE_WRITEERROR;
    }

    WCHAR* p = wcsrchr(LocalName, '\\');
    if (p)
        RemoveInalidCharsW(p+1);  // Changes the name passed in!

    WCHAR remotedir[wdirtypemax];
    SERVERID serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir, countof(remotedir)-1);
    if (serverid == NULL)
        return FS_FILE_READERROR;
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (ConnectSettings)
        ConnectSettings->lastpercent=0;

    err = ProgressProcT(PluginNumber, RemoteName, LocalName, 0);
    if (err)
        return FS_FILE_USERABORT;
    if (OverWrite)
        DeleteFileT(LocalName);
    else {
        if (!Resume && FileExistsT(LocalName)) {
            // Resume isn't possible because we cannot know
            // which <CR> characters were already in the original
            // file,  and which were added during the download
            pConnectSettings ConnectSettings = (pConnectSettings)serverid;
            BOOL TextMode = (ConnectSettings->unixlinebreaks == 1) && SftpDetermineTransferModeW(RemoteName);
            if (TextMode)
                return SFTP_FAILED;
            else
                return FS_FILE_EXISTSRESUMEALLOWED;
        }
    }

    __int64 filesize = (((__int64)ri->SizeHigh) << 32) + ri->SizeLow;
    
    while (true) {  // auto-resume loop
        switch (SftpDownloadFileW(serverid, remotedir, LocalName, true, filesize, &ri->LastWriteTime, Resume)) {
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

int WINAPI FsGetFile(char* RemoteName, char* LocalName, int CopyFlags, RemoteInfoStruct* ri)
{
    WCHAR RemoteNameW[wdirtypemax], LocalNameW[wdirtypemax];
    return FsGetFileW(awfilenamecopy(RemoteNameW, RemoteName), awfilenamecopy(LocalNameW, LocalName), CopyFlags, ri);
}

int WINAPI FsPutFileW(WCHAR* LocalName, WCHAR* RemoteName, int CopyFlags)
{
    int err;
    BOOL OverWrite, Resume, Move;

    OverWrite = CopyFlags & FS_COPYFLAGS_OVERWRITE;
    Resume = CopyFlags & FS_COPYFLAGS_RESUME;
    Move = CopyFlags & FS_COPYFLAGS_MOVE;

    // Auto-overwrites files -> return error if file exists
    if ((CopyFlags & (FS_COPYFLAGS_EXISTS_SAMECASE | FS_COPYFLAGS_EXISTS_DIFFERENTCASE)) && !(OverWrite | Resume))
        return FS_FILE_EXISTSRESUMEALLOWED;

    if (wcslen(RemoteName) < 3)
        return FS_FILE_WRITEERROR;

    err = ProgressProcT(PluginNumber, LocalName, RemoteName, 0);
    if (err)
        return FS_FILE_USERABORT;

    WCHAR remotedir[wdirtypemax];
    
    SERVERID serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir, countof(remotedir)-1);
    if (serverid == NULL)
        return FS_FILE_READERROR;
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (ConnectSettings)
        ConnectSettings->lastpercent = 0;

    switch (SftpUploadFileW(serverid, LocalName, remotedir, Resume, (CopyFlags & FS_COPYFLAGS_EXISTS_SAMECASE) == 0)) {
        case SFTP_OK:          return FS_FILE_OK;
        case SFTP_EXISTS:      return SftpSupportsResume(serverid) ? FS_FILE_EXISTSRESUMEALLOWED : FS_FILE_EXISTS;
        case SFTP_READFAILED:  return FS_FILE_READERROR;
        case SFTP_WRITEFAILED: return FS_FILE_WRITEERROR;
        case SFTP_ABORT:       return FS_FILE_USERABORT;
    }
    return FS_FILE_NOTFOUND;
}

int WINAPI FsPutFile(char* LocalName, char* RemoteName, int CopyFlags)
{
    WCHAR LocalNameW[wdirtypemax], RemoteNameW[wdirtypemax];
    return FsPutFileW(awfilenamecopy(LocalNameW, LocalName), awfilenamecopy(RemoteNameW, RemoteName), CopyFlags);
}

BOOL WINAPI FsDeleteFileW(WCHAR* RemoteName)
{
    if (wcslen(RemoteName) < 3)
        return false;

    WCHAR* p = wcschr(RemoteName+1, '\\');
    if (p) {
        WCHAR remotedir[wdirtypemax];
        SERVERID serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir, countof(remotedir)-1);
        if (serverid == NULL)
            return false;
        pConnectSettings ConnectSettings = (pConnectSettings)serverid;
        if (ConnectSettings)
            ConnectSettings->lastpercent = 0;
        return SftpDeleteFileW(serverid, remotedir, false) == SFTP_OK;
    } else {  // delete server
        char remotedir[wdirtypemax];
        walcopy(remotedir, RemoteName+1, sizeof(remotedir)-1);
        if (_stricmp(remotedir, s_f7newconnection) != 0 && _stricmp(remotedir, s_quickconnect) != 0) {
            if (DeleteServerFromIni(remotedir, inifilename)) {
                if (CryptProc)
                    CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_DELETE_PASSWORD, remotedir, NULL, 0);
                return true;
            } else
                return false;
        }
    }
    return false;
}

BOOL WINAPI FsDeleteFile(char* RemoteName)
{
    WCHAR RemoteNameW[wdirtypemax];
    return FsDeleteFileW(awfilenamecopy(RemoteNameW, RemoteName));
}

BOOL WINAPI FsRemoveDirW(WCHAR* RemoteName)
{
    if (wcslen(RemoteName) < 1)
        return false;

    WCHAR* p = wcschr(RemoteName+1, '\\');
    if (p) {
        WCHAR remotedir[wdirtypemax];
        SERVERID serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir, countof(remotedir)-1);
        if (serverid == NULL)
            return false;
        pConnectSettings ConnectSettings = (pConnectSettings)serverid;
        if (ConnectSettings)
            ConnectSettings->lastpercent=0;

        return (SftpDeleteFileW(serverid, remotedir, true) == SFTP_OK);
    }
    return false;
}

BOOL WINAPI FsRemoveDir(char* RemoteName)
{
    WCHAR RemoteNameW[wdirtypemax];
    return FsRemoveDirW(awfilenamecopy(RemoteNameW, RemoteName));
}

BOOL WINAPI FsSetAttr(char* RemoteName, int NewAttr)
{
    char remotedir[wdirtypemax];
    SERVERID serverid = GetServerIdAndRelativePathFromPath(RemoteName, remotedir, sizeof(remotedir)-1);
    if (serverid == NULL)
        return false;
    
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (ConnectSettings)
        ConnectSettings->lastpercent = 0;
    return SftpSetAttr(serverid, remotedir, NewAttr) == SFTP_OK;
}

BOOL WINAPI FsSetTimeW(WCHAR* RemoteName, FILETIME *CreationTime, FILETIME *LastAccessTime, FILETIME *LastWriteTime)
{
    WCHAR remotedir[wdirtypemax];
    SERVERID serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir, countof(remotedir)-1);
    if (serverid == NULL)
        return false;

    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (ConnectSettings)
        ConnectSettings->lastpercent=0;
    return SftpSetDateTimeW(serverid, remotedir, LastWriteTime) == SFTP_OK;
}

BOOL WINAPI FsSetTime(char* RemoteName, FILETIME *CreationTime, FILETIME *LastAccessTime, FILETIME *LastWriteTime)
{
    WCHAR RemoteNameW[wdirtypemax];
    return FsSetTimeW(awfilenamecopy(RemoteNameW, RemoteName), CreationTime, LastAccessTime, LastWriteTime);
}

void WINAPI FsStatusInfo(char* RemoteDir, int InfoStartEnd, int InfoOperation)
{
    if (strlen(RemoteDir) < 2)
        if (InfoOperation == FS_STATUS_OP_DELETE || InfoOperation == FS_STATUS_OP_RENMOV_MULTI)
            if (InfoStartEnd == FS_STATUS_START)
                disablereading = true;
            else
                disablereading = false;
    if (InfoOperation == FS_STATUS_OP_GET_MULTI_THREAD || InfoOperation == FS_STATUS_OP_PUT_MULTI_THREAD) {
        if (InfoStartEnd == FS_STATUS_START) {
            char DisplayName[MAX_PATH];
            char* oldpass = NULL;
            GetDisplayNameFromPath(RemoteDir, DisplayName, sizeof(DisplayName)-1);
            // get password from main thread
            void* oldserverid = GetServerIdFromName(DisplayName, mainthreadid);
            pConnectSettings ConnectSettings = (pConnectSettings)oldserverid;
            if (ConnectSettings) {
                oldpass = ConnectSettings->password;
                if (!oldpass[0])
                    oldpass = NULL;
            }
            void* serverid = SftpConnectToServer(DisplayName, inifilename, oldpass);
            if (serverid)
                SetServerIdForName(DisplayName, serverid);
        } else {
            FsDisconnect(RemoteDir);
        }
    }
}

void WINAPI FsGetDefRootName(char* DefRootName, int maxlen)
{
    strlcpy(DefRootName, defrootname, maxlen);
}

// use default location,  but our own ini file name!
void WINAPI FsSetDefaultParams(FsDefaultParamStruct* dps)
{
    strlcpy(inifilename, dps->DefaultIniName, MAX_PATH-1);
    char* p = strrchr(inifilename, '\\');
    if (p)
        p[1] = 0;
    else
        inifilename[0] = 0;
    strlcat(inifilename, defininame, sizeof(inifilename)-1);

    // copy ini template from plugin dir to ini location if it exists!
    char templatename[MAX_PATH];
    if (GetModuleFileName(hinst, templatename, sizeof(templatename)-1)) {
        char* p = strrchr(templatename, '\\');
        if (p) {
            p[1] = 0;
            strlcat(templatename, templatefile, sizeof(templatename)-1);
        }
        CopyFile(templatename, inifilename, true);  // only copy if target doesn't exist
    }
}

int WINAPI FsExtractCustomIcon(char* RemoteName, int ExtractFlags, HICON* TheIcon)
{
    if (strlen(RemoteName) > 1) {
        char* p = strchr(RemoteName+1, '\\');
        if (p == NULL) {   // a server!
            if (_stricmp(RemoteName+1, s_f7newconnection) != 0) {
                bool sm;
                char remotedir[wdirtypemax];
                SERVERID serverid = GetServerIdAndRelativePathFromPath(RemoteName, remotedir, sizeof(remotedir)-1);
                sm = (ExtractFlags & FS_ICONFLAG_SMALL) != 0;
                // show different icon when connected!
                if (serverid == NULL)
                    *TheIcon=LoadIcon(hinst, MAKEINTRESOURCE(sm ? IDI_ICON1SMALL : IDI_ICON1));
                else
                    *TheIcon=LoadIcon(hinst, MAKEINTRESOURCE(sm ? IDI_ICON2SMALL : IDI_ICON2));
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

int __stdcall FsServerSupportsChecksumsW(WCHAR* RemoteName)
{
    WCHAR remotedir[wdirtypemax];
    SERVERID serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir, countof(remotedir)-1);
    if (serverid == NULL)
        return 0;

    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (ConnectSettings)
        ConnectSettings->lastpercent = 0;
    return SftpServerSupportsChecksumsW(serverid, remotedir);
}

int __stdcall FsServerSupportsChecksums(char* RemoteName)
{
    WCHAR RemoteNameW[wdirtypemax];
    return FsServerSupportsChecksumsW(awfilenamecopy(RemoteNameW, RemoteName));
}

HANDLE __stdcall FsStartFileChecksumW(int ChecksumType, WCHAR* RemoteName)
{
    WCHAR remotedir[wdirtypemax];
    SERVERID serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir, countof(remotedir)-1);
    if (serverid == NULL)
        return 0;

    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (ConnectSettings)
        ConnectSettings->lastpercent = 0;
    return SftpStartFileChecksumW(ChecksumType, serverid, remotedir);
}

HANDLE __stdcall FsStartFileChecksum(int ChecksumType, char* RemoteName)
{
    WCHAR RemoteNameW[wdirtypemax];
    return FsStartFileChecksumW(ChecksumType, awfilenamecopy(RemoteNameW, RemoteName));
}


int __stdcall FsGetFileChecksumResultW(BOOL WantResult, HANDLE ChecksumHandle, WCHAR* RemoteName, char* checksum, int maxlen)
{
    WCHAR remotedir[wdirtypemax];
    SERVERID serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir, countof(remotedir)-1);
    if (serverid == NULL)
        return 0;

    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (ConnectSettings)
        ConnectSettings->lastpercent = 0;
    return SftpGetFileChecksumResultW(WantResult, ChecksumHandle, serverid, checksum, maxlen);
}

int __stdcall FsGetFileChecksumResult(BOOL WantResult, HANDLE ChecksumHandle, char* RemoteName, char* checksum, int maxlen)
{
    WCHAR RemoteNameW[wdirtypemax];
    return FsGetFileChecksumResultW(WantResult, ChecksumHandle, awfilenamecopy(RemoteNameW, RemoteName), checksum, maxlen);
}

