#pragma once

#define SERVERID void*
#define SERVERHANDLE void*

typedef void SAVECALLBACK(char* inifilename, SERVERID serverid);

void InitMultiServer();
int LoadServersFromIni(char* inifilename, char* quickconnectname);
BOOL DeleteServerFromIni(char* servername, char* inifilename);
int CopyMoveServerInIni(char* oldservername, char* newservername, BOOL Move, BOOL OverWrite, char* inifilename);
void FreeServerList();

SERVERID GetServerIdFromName(char* servername, DWORD threadid);
BOOL SetServerIdForName(char* displayname, SERVERID newid);

void GetDisplayNameFromPath(char* Path, char* DisplayName, int maxlen);

SERVERHANDLE FindFirstServer(char* displayname, int maxlen);
SERVERHANDLE FindNextServer(SERVERHANDLE searchhandle, char* displayname, int maxlen);

