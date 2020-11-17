#include "utils.h"
#include "multiserver.h"
#include "sftpplug.h"

// save servers in linked list

typedef struct _SERVERENTRY {
    struct _SERVERENTRY * next;
    SERVERID   serverid;          // object from LibSSH2
    DWORD      threadid;          // for background threads only!
    CHAR       displayname[MAX_PATH];
    bool       serverupdated;
} SERVERENTRY, *PSERVERENTRY;

PSERVERENTRY server_linked_list = NULL;
PSERVERENTRY background_linked_list = NULL;
CRITICAL_SECTION bgcriticalsection = {0};
bool bgcriticalsectioninitialized = false;
extern DWORD mainthreadid;

/* FIXME: create class ServerList */

void InitMultiServer() noexcept
{
    if (!bgcriticalsectioninitialized) {
        bgcriticalsectioninitialized = true;
        InitializeCriticalSection(&bgcriticalsection);  /* FIXME: DeleteCriticalSection not used! */
    }
}

/* =============================================================================================== */

#define MS_FLAG_BKGR           0x0001
#define MS_FLAG_NOLINK         0x0002
#define MS_FLAG_ADDTOHEAD      0x0004
#define MS_FLAG_FREEALL        0x0008

__forceinline
static PSERVERENTRY GetHeadSrvEntry(int flags) noexcept
{
    return (flags & MS_FLAG_BKGR) ? background_linked_list : server_linked_list;
}

__forceinline
static void SetHeadSrvEntry(PSERVERENTRY head, int flags) noexcept
{
    if (flags & MS_FLAG_BKGR)
        background_linked_list = head;
    else
        server_linked_list = head;
}

__forceinline
static PSERVERENTRY GetTailSrvEntry(int flags = 0) noexcept
{
    PSERVERENTRY tail = NULL;
    for (PSERVERENTRY ps = GetHeadSrvEntry(flags); ps; ps = ps->next) {
        tail = ps;
    }
    return tail;
}

__forceinline
static PSERVERENTRY GetPrevSrvEntry(PSERVERENTRY se, int flags = 0) noexcept
{
    PSERVERENTRY prev = NULL;
    for (PSERVERENTRY ps = GetHeadSrvEntry(flags); ps; ps = ps->next) {
        if (ps == se)
            return prev;
        prev = ps;
    }
    return prev;
}

__forceinline
static void SrvListClearUpdateFlag(int flags = 0) noexcept
{
    for (PSERVERENTRY ps = GetHeadSrvEntry(flags); ps; ps = ps->next) {
        ps->serverupdated = false;
    }
}

__forceinline
static PSERVERENTRY GetSrvEntryByThreadAndName(DWORD tid, LPCSTR name, int flags = 0) noexcept
{
    for (PSERVERENTRY ps = GetHeadSrvEntry(flags); ps; ps = ps->next) {
        if (tid && ps->threadid != tid)
            continue;
        if (_stricmp(ps->displayname, name) == 0)
            return ps;
    }
    return NULL;
}

__forceinline
static PSERVERENTRY GetSrvEntryByName(LPCSTR name, int flags = 0) noexcept
{
    return GetSrvEntryByThreadAndName(0, name, flags);
}

static PSERVERENTRY CreateSrvEntry(LPCSTR name, int flags = 0) noexcept
{
    PSERVERENTRY newentry = (PSERVERENTRY)malloc(sizeof(SERVERENTRY));
    if (!newentry)
        return NULL;
    memset(newentry, 0, sizeof(SERVERENTRY));
    strlcpy(newentry->displayname, name, sizeof(newentry->displayname)-1);
    newentry->serverupdated = true;
    if ((flags & MS_FLAG_NOLINK) == 0) {
        if (flags & MS_FLAG_ADDTOHEAD) {
            newentry->next = GetHeadSrvEntry(flags);
            SetHeadSrvEntry(newentry, flags);
        } else {    
            PSERVERENTRY tail = GetTailSrvEntry(flags);
            if (tail)
                tail->next = newentry;
            else
                SetHeadSrvEntry(newentry, flags);
        }
    }
    return newentry;
}

static void DestroySrvEntry(PSERVERENTRY se, int flags = 0) noexcept
{
    if (!se)
        return;
    PSERVERENTRY prev_entry = GetPrevSrvEntry(se);
    if (prev_entry)
        prev_entry->next = se->next;
    else
        SetHeadSrvEntry(se->next, flags);
    if (flags & MS_FLAG_FREEALL) {
        if (se->serverid)
            free(se->serverid);     /* FIXME: Doesn't this object have a destructor? */
    }
    free(se);
}

static bool SetServerId(PSERVERENTRY se, SERVERID newid, int flags = 0) noexcept
{
    if (!se)
        return false;
    if (se->serverid)
        free(se->serverid);  /* FIXME: maybe this object has its own destructor? */
    se->serverid = newid;
    return true;
}

/* =============================================================================================== */

/* FIXME: use Unicode name for working files in local user directory */
int LoadServersFromIni(LPCSTR inifilename, LPCSTR quickconnectname) noexcept
{
    // Retrieve server list
    int servercount = 0;
    char serverlist[65535];

    bool updating = (server_linked_list != NULL);
    if (updating) { // list exists -> update!
        SrvListClearUpdateFlag();
    }
    GetPrivateProfileString(NULL, NULL, "", serverlist, sizeof(serverlist), inifilename);
    LPSTR p = serverlist;
    while (p[0]) {
        // Each server MUST have the value "server"!!!
        char server[512];
        GetPrivateProfileString(p, "server", "", server, sizeof(server), inifilename);
        if (server[0]) {
            servercount++;
            PSERVERENTRY thisentry = NULL;
            if (updating) {  // look if entry already exists
                thisentry = GetSrvEntryByName(p);
                if (thisentry)
                    thisentry->serverupdated = true;
            }
            if (!thisentry) {
                CreateSrvEntry(p);
            }
        }
        p += strlen(p) + 1;
    }
    // now delete all servers which aren't currently connected, and no longer in ini file
    if (updating) { // list exists -> update!
        PSERVERENTRY se = server_linked_list;
        while (se) {            
            bool destroy = true;
            if (se->serverupdated || se->serverid)
                destroy = false;   /* skip */
            if (quickconnectname && strcmp(se->displayname, quickconnectname) == 0)
                destroy = false;   /* skip */
            PSERVERENTRY xse = se;
            se = se->next;
            if (destroy)
                DestroySrvEntry(xse);   /* FIXME: use MS_FLAG_FREEALL ??? */
        }
    }
    // add "quick connect" entry as first list item
    if (!updating && quickconnectname) {
        PSERVERENTRY newentry = CreateSrvEntry(quickconnectname, MS_FLAG_ADDTOHEAD);
        if (newentry) {
            servercount++;
        } else {
            quickconnectname = false;
        }
    }
    if (!quickconnectname)          // actually it's never 0 if there is a "Quick connection!"
        if (servercount == 0)
            server_linked_list = NULL;

    return servercount;
}

bool DeleteServerFromIni(LPCSTR servername, LPCSTR inifilename) noexcept
{
    return WritePrivateProfileString(servername, NULL, NULL, inifilename) ? true : false;
}

int CopyMoveServerInIni(LPCSTR oldservername, LPCSTR newservername, bool Move, bool OverWrite, LPCSTR inifilename) noexcept
{
    char captlist[1024];
    if (_stricmp(oldservername, newservername) == 0)
        return FS_FILE_OK;

    // now copy the options
    GetPrivateProfileString(oldservername, NULL, "", captlist, sizeof(captlist)-1, inifilename);
    if (captlist[0]) {
        if (!OverWrite) {
            char testlist[100];
            // check whether server with new name already exists!
            testlist[0] = 0;
            GetPrivateProfileString(newservername, NULL, "", testlist, sizeof(testlist)-1, inifilename);
            if (testlist[0])
                return FS_FILE_EXISTS;
        }

        // Kill target section to delete fields not present in source section
        DeleteServerFromIni(newservername, inifilename);

        LPSTR pcapt = captlist;
        while (pcapt[0]) {
            char valuebuf[1024];
            GetPrivateProfileString(oldservername, pcapt, "", valuebuf, sizeof(valuebuf)-1, inifilename);
            WritePrivateProfileString(newservername, pcapt, valuebuf, inifilename);
            pcapt += strlen(pcapt) + 1;
        }
        if (Move)
            DeleteServerFromIni(oldservername, inifilename);
        return FS_FILE_OK;
    }
    return FS_FILE_NOTFOUND;
}

/* FIXME: This function is not used anywhere! */
void FreeServerList() noexcept
{
    if (server_linked_list) {
        PSERVERENTRY se = server_linked_list;
        while (se) {
            PSERVERENTRY xse = se;
            se = se->next;
            DestroySrvEntry(xse, MS_FLAG_FREEALL);
        }
    }
}

static SERVERID GetServerIdByThreadAndName(DWORD tid, LPCSTR displayname, int flags = 0) noexcept
{
    PSERVERENTRY se = GetSrvEntryByThreadAndName(tid, displayname, flags);
    return (se != NULL) ? se->serverid : NULL;
}

SERVERID GetServerIdFromName(LPCSTR displayname, DWORD threadid) noexcept
{
    SERVERID rv = NULL;
    if (threadid == mainthreadid) {
        return GetServerIdByThreadAndName(0, displayname);
    }
    EnterCriticalSection(&bgcriticalsection);    /* FIXME: replace to RAII object */
    {
        rv = GetServerIdByThreadAndName(threadid, displayname, MS_FLAG_BKGR);
    }
    LeaveCriticalSection(&bgcriticalsection);
    return rv;
}

bool SetServerIdForName(LPCSTR displayname, SERVERID newid) noexcept
{
    bool rv = false;
    DWORD tid = GetCurrentThreadId();
    if (tid == mainthreadid) {
        PSERVERENTRY se = GetSrvEntryByName(displayname);
        return SetServerId(se, newid, 0);
    }
    EnterCriticalSection(&bgcriticalsection);  /* FIXME: replace to RAII object */
    {
        PSERVERENTRY se = GetSrvEntryByThreadAndName(tid, displayname, MS_FLAG_BKGR);
        if (se) {
            if (newid) {
                SetServerId(se, newid, MS_FLAG_BKGR);
            } else {
                DestroySrvEntry(se, MS_FLAG_BKGR);  /* FIXME: use MS_FLAG_FREEALL ??? */
            }
            rv = true;
        } else {
            // insert at the beginning!
            PSERVERENTRY newentry = CreateSrvEntry(displayname, MS_FLAG_BKGR | MS_FLAG_ADDTOHEAD);
            if (newentry) {
                newentry->threadid = tid;
                SetServerId(newentry, newid, MS_FLAG_BKGR);
                /* FIXME: set `rv` to true? */
            }
        }
    }
    LeaveCriticalSection(&bgcriticalsection);
    return rv;   
}

void GetDisplayNameFromPath(LPCSTR Path, LPSTR DisplayName, size_t maxlen) noexcept
{
    LPSTR p = (LPSTR)Path;
    while (*p == '\\' || *p == '/')
        p++;
    strlcpy(DisplayName, p, maxlen);
    p = DisplayName;
    while (*p && *p != '\\' && *p != '/')
        p++;
    *p = 0;
}

SERVERHANDLE FindFirstServer(LPSTR displayname, size_t maxlen) noexcept
{
    if (server_linked_list) {
        strlcpy(displayname, server_linked_list->displayname, maxlen);
        return (SERVERHANDLE)server_linked_list;
    }
    return NULL;
}

SERVERHANDLE FindNextServer(SERVERHANDLE searchhandle, LPSTR displayname, size_t maxlen) noexcept
{
    if (searchhandle) {
        PSERVERENTRY thisentry = (PSERVERENTRY)searchhandle;
        thisentry = thisentry->next;
        if (thisentry) {
            strlcpy(displayname, thisentry->displayname, maxlen);
            return (SERVERHANDLE)thisentry;
        }
    }
    return NULL;
}

