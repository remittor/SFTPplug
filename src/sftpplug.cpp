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


/* FIXME: make class aka ProgressInfo */
static bool MessageLoop(SERVERID serverid) noexcept
{
    bool aborted = false;
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (!g_wfx.m_cb.ProgressProc)
        return false;
    if (ConnectSettings && get_ticks_between(ConnectSettings->lastpercenttime) > 250) {   /* FIXME: magic number! */
        // important: also call AFTER soft_aborted is true!!!
        aborted = (0 != g_wfx.m_cb.ProgressProc(PluginNumber, NULL, NULL, ConnectSettings->lastpercent));
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

/* FIXME: make class aka ProgressInfo */
bool UpdatePercentBar(SERVERID serverid, int percent) noexcept
{
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (ConnectSettings)
        ConnectSettings->lastpercent = percent;  // used for MessageLoop below

    return MessageLoop(serverid);  // This actually sets the percent bar!
}


