#include <windows.h>
#include "multiserver.h"
#include "utils.h"

// save servers in linked list

typedef struct {
    char displayname[260];
    SERVERID serverid;
    void* next;
    BOOL serverupdated;
    DWORD threadid;    // for background threads only!
} SERVERENTRY, *PSERVERENTRY;

PSERVERENTRY server_linked_list = NULL;
PSERVERENTRY background_linked_list = NULL;
CRITICAL_SECTION bgcriticalsection = {0};
BOOL bgcriticalsectioninitialized = false;
extern DWORD mainthreadid;

void InitMultiServer()
{
    if (!bgcriticalsectioninitialized) {
        bgcriticalsectioninitialized = true;
        InitializeCriticalSection(&bgcriticalsection);
    }
}

int LoadServersFromIni(char* inifilename, char* quickconnectname)
{
    // Retrieve server list
    int servercount = 0;
    char serverlist[8192];
    PSERVERENTRY preventry = NULL;
    BOOL updating = (server_linked_list != NULL);
    if (updating) { // list exists -> update!
        PSERVERENTRY thisentry;
        thisentry = server_linked_list;
        while (thisentry) {
            thisentry->serverupdated = false;
            preventry = thisentry;
            thisentry = (PSERVERENTRY)(thisentry->next);
        }
    }
    GetPrivateProfileString(NULL, NULL, "", serverlist, sizeof(serverlist), inifilename);
    char *p = serverlist;
    while (p[0]) {
        // Each server MUST have the value "server"!!!
        char server[512];
        GetPrivateProfileString(p, "server", "", server, sizeof(server), inifilename);
        if (server[0]) {
            PSERVERENTRY newentry;
            servercount++;
            BOOL serverfound = false;
            if (updating) {  // look if entry already exists
                PSERVERENTRY thisentry = server_linked_list;
                while (thisentry) {
                    if (stricmp(thisentry->displayname, p) == 0) {
                        thisentry->serverupdated = true;
                        serverfound = true;
                        break;
                    }
                    thisentry = (PSERVERENTRY)(thisentry->next);
                }
            }
            if (!serverfound) {
                newentry = (PSERVERENTRY)malloc(sizeof(SERVERENTRY));
                if (newentry) {
                    strlcpy(newentry->displayname, p, sizeof(newentry->displayname)-1);
                    newentry->serverid = NULL;
                    newentry->next = NULL;
                    newentry->serverupdated = true;
                }
                if (preventry)
                    preventry->next = newentry;
                else
                    server_linked_list = newentry;
                preventry = newentry;
            }
        }
        p += strlen(p) + 1;
    }
    // now delete all servers which aren't currently connected,  and no longer in ini file
    if (updating) { // list exists -> update!
        PSERVERENTRY thisentry, preventry, nextentry;
        thisentry = server_linked_list;
        preventry = NULL; 
        BOOL needrelink = false; // need to re-link linked list
        while (thisentry) {
            if (!thisentry->serverupdated && thisentry->serverid == NULL && (quickconnectname == NULL || strcmp(thisentry->displayname, quickconnectname) != 0)) {
                if (preventry)
                    preventry->next = NULL;
                nextentry = (PSERVERENTRY)(thisentry->next);
                free(thisentry);
                needrelink = true;
            } else {
                if (needrelink) {
                    needrelink = false;
                    if (preventry)
                        preventry->next = thisentry;
                    else
                        server_linked_list = thisentry; // the first was deleted
                }
                preventry = thisentry;
                nextentry = (PSERVERENTRY)(thisentry->next);
            }
            thisentry = nextentry;
        }
    }
    // add "quick connect" entry as first list item
    if (!updating && quickconnectname) {
        PSERVERENTRY newentry = (PSERVERENTRY)malloc(sizeof(SERVERENTRY));
        if (newentry) {
            strcpy(newentry->displayname, quickconnectname);
            newentry->serverid = NULL;
            newentry->next = server_linked_list;
            newentry->serverupdated = true;
            server_linked_list = newentry;
            servercount++;
        }
    }
    if (!quickconnectname)          // actually it's never 0 if there is a "Quick connection!"
        if (servercount == 0)
            server_linked_list = NULL;
    return servercount;
}

BOOL DeleteServerFromIni(char* servername, char* inifilename)
{
    return WritePrivateProfileString(servername, NULL, NULL, inifilename);
}

int CopyMoveServerInIni(char* oldservername, char* newservername, BOOL Move, BOOL OverWrite, char* inifilename)
{
    char captlist[1024];
    if (stricmp(oldservername, newservername) == 0)
        return 0;

    // now copy the options
    GetPrivateProfileString(oldservername, NULL, "", captlist, sizeof(captlist)-1, inifilename);
    if (captlist[0]) {
        if (!OverWrite) {
            char testlist[100];
            // check whether server with new name already exists!
            testlist[0] = 0;
            GetPrivateProfileString(newservername, NULL, "", testlist, sizeof(testlist)-1, inifilename);
            if (testlist[0])
                return 1;
        }

        // Kill target section to delete fields not present in source section
        DeleteServerFromIni(newservername, inifilename);

        char* pcapt = captlist;
        while (pcapt[0]) {
            char valuebuf[1024];
            GetPrivateProfileString(oldservername, pcapt, "", valuebuf, sizeof(valuebuf)-1, inifilename);
            WritePrivateProfileString(newservername, pcapt, valuebuf, inifilename);
            pcapt += strlen(pcapt) + 1;
        }
        if (Move)
            DeleteServerFromIni(oldservername, inifilename);
        return 0;
    }
    return 2;
}

void FreeServerList()
{
    if (server_linked_list) {
        PSERVERENTRY thisentry;
        thisentry = server_linked_list;
        while (thisentry) {
            PSERVERENTRY nextentry = (PSERVERENTRY)(thisentry->next);
            if (thisentry->serverid)
                free(thisentry->serverid);
            free(thisentry);
            thisentry = nextentry;
        }
    }
}

SERVERID GetServerIdFromName(char* displayname, DWORD threadid)
{
    if (threadid == mainthreadid) {
        if (server_linked_list) {
            PSERVERENTRY thisentry;
            thisentry = server_linked_list;
            while (thisentry) {
                if (stricmp(thisentry->displayname, displayname) == 0)
                    return thisentry->serverid;
                thisentry = (PSERVERENTRY)(thisentry->next);
            }
        }
    } else {
        EnterCriticalSection(&bgcriticalsection);
        __try {
            if (background_linked_list) {
                PSERVERENTRY thisentry;
                thisentry = background_linked_list;
                while (thisentry) {
                    if (stricmp(thisentry->displayname, displayname) == 0 && thisentry->threadid == threadid)
                        return thisentry->serverid;
                    thisentry = (PSERVERENTRY)(thisentry->next);
                }
            }
        }
        __finally {
            LeaveCriticalSection(&bgcriticalsection);
        }
    }
    return NULL;
}

BOOL SetServerIdForName(char* displayname, SERVERID newid)
{
    DWORD id = GetCurrentThreadId();
    if (id == mainthreadid) {
        if (server_linked_list) {
            PSERVERENTRY thisentry;
            thisentry = server_linked_list;
            while (thisentry) {
                if (stricmp(thisentry->displayname, displayname) == 0) {
                    if (thisentry->serverid)
                        free(thisentry->serverid);
                    thisentry->serverid = newid;
                    return true;
                }
                thisentry = (PSERVERENTRY)(thisentry->next);
            }
        }
    } else {
        EnterCriticalSection(&bgcriticalsection);
        __try {
            if (background_linked_list) {
                PSERVERENTRY thisentry, preventry;
                preventry = NULL;
                thisentry = background_linked_list;
                while (thisentry) {
                    if (stricmp(thisentry->displayname, displayname) == 0 &&
                        thisentry->threadid == id) {
                        if (thisentry->serverid)
                            free(thisentry->serverid);
                        if (newid)
                            thisentry->serverid = newid;
                        else {
                            // remove from linked list!
                            if (!preventry)
                                background_linked_list = (PSERVERENTRY)(thisentry->next);
                            else
                                preventry->next = thisentry->next;
                            free(thisentry);
                        }
                        return true;
                    }
                    preventry = thisentry;
                    thisentry = (PSERVERENTRY)(thisentry->next);
                }
            }
            PSERVERENTRY newentry = (PSERVERENTRY)malloc(sizeof(SERVERENTRY));
            if (newentry) {
                strcpy(newentry->displayname, displayname);
                newentry->serverid = newid;
                newentry->serverupdated = true;
                newentry->threadid = id;
                // insert at the beginning!
                newentry->next = background_linked_list;
                background_linked_list = newentry;
            }
        }
        __finally {
            LeaveCriticalSection(&bgcriticalsection);
        }
    }
    return false;
}

void GetDisplayNameFromPath(char* Path, char* DisplayName, int maxlen)
{
    char* p = Path;
    while (p[0] == '\\' || p[0] == '/')
        p++;
    strlcpy(DisplayName, p, maxlen);
    p = DisplayName;
    while (p[0] != 0 && p[0] != '\\' && p[0] != '/')
        p++;
    p[0] = 0;
}

SERVERHANDLE FindFirstServer(char* displayname, int maxlen)
{
    if (server_linked_list) {
        strlcpy(displayname, server_linked_list->displayname, maxlen);
        return server_linked_list;
    }
    return NULL;
}

SERVERHANDLE FindNextServer(SERVERHANDLE searchhandle, char* displayname, int maxlen)
{
    if (searchhandle) {
        PSERVERENTRY thisentry = (PSERVERENTRY)(searchhandle);
        thisentry = (PSERVERENTRY)thisentry->next;
        if (thisentry) {
            strlcpy(displayname, thisentry->displayname, maxlen);
            return thisentry;
        }
    }
    return NULL;
}

