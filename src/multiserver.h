#pragma once

/* FIXME: create class ServerList */

typedef LPVOID  SERVERID;
typedef LPVOID  SERVERHANDLE;

void InitMultiServer() noexcept;
int  LoadServersFromIni(LPCSTR inifilename, LPCSTR quickconnectname) noexcept;
bool DeleteServerFromIni(LPCSTR servername, LPCSTR inifilename) noexcept;
int  CopyMoveServerInIni(LPCSTR oldservername, LPCSTR newservername, bool Move, bool OverWrite, LPCSTR inifilename) noexcept;
void FreeServerList() noexcept;

SERVERID GetServerIdFromName(LPCSTR servername, DWORD threadid) noexcept;
bool SetServerIdForName(LPCSTR displayname, SERVERID newid) noexcept;

void GetDisplayNameFromPath(LPCSTR Path, LPSTR DisplayName, size_t maxlen) noexcept;

SERVERHANDLE FindFirstServer(LPSTR displayname, size_t maxlen) noexcept;
SERVERHANDLE FindNextServer(SERVERHANDLE searchhandle, LPSTR displayname, size_t maxlen) noexcept;

