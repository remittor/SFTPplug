#pragma once

#include "utils.h"
#include "plugin.h"

extern HINSTANCE hinst;
extern int PluginNumber;
extern int CryptoNumber;
extern DWORD mainthreadid;

extern tProgressProc  ProgressProc;
extern tProgressProcW ProgressProcW;
extern tLogProc       LogProc;
extern tLogProcW      LogProcW;
extern tRequestProc   RequestProc;
extern tRequestProcW  RequestProcW;
extern tCryptProc     CryptProc;

extern bool CryptCheckPass;

extern char pluginname[];
extern char inifilename[MAX_PATH];
extern char s_f7newconnection[32];
extern char s_quickconnect[32];
extern WCHAR s_f7newconnectionW[32];
extern WCHAR s_quickconnectW[32];


void LogMsg(LPCSTR fmt, ...) noexcept;
void ShowStatus(LPCSTR status) noexcept;
void ShowStatusW(LPCWSTR status) noexcept;
bool UpdatePercentBar(LPVOID serverid, int percent) noexcept;

