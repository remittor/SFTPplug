#include "sftpplug.h"
#include "excatch.h"
#include <string>

HANDLE g_hInstance = NULL;
wfx::Plugin g_wfx;


extern "C" BOOL WINAPI _DllMainCRTStartup(HINSTANCE hInstDLL, DWORD fdwReason, LPVOID lpReserved);

BOOL WINAPI DllMain(HINSTANCE hInstDLL, DWORD fdwReason, LPVOID lpReserved) noexcept
{
    volatile LPVOID ep = _DllMainCRTStartup;

    if (fdwReason == DLL_PROCESS_ATTACH) {
        DWORD tid = GetCurrentThreadId();
        g_hInstance = hInstDLL;
        LOGn("SFTP Plugin Loaded ===================== Thread ID = 0x%X ========", tid);
        g_wfx.init(hInstDLL, tid);
    }
    if (fdwReason == DLL_PROCESS_DETACH) {
        DWORD tid = g_wfx.get_main_thread_id();
        LOGn("SFTP Plugin unload! -------------------------------- 0x%X --------", tid);
    }
    return TRUE;
}

#define WfxDllExport

WfxDllExport
int WINAPI FsGetBackgroundFlags(void)
{
    #pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    LOGt("%s: BG_DOWNLOAD | BG_UPLOAD | BG_ASK_USER", __func__);
    return BG_DOWNLOAD | BG_UPLOAD | BG_ASK_USER;
}

WfxDllExport
void WINAPI FsGetDefRootName(LPSTR DefRootName, int maxlen)
{
    #pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    LOGt("%s: DefRootName = \"%s\"", __func__, wfx::defrootname);
    strlcpy(DefRootName, wfx::defrootname, maxlen);
}

WfxDllExport
int WINAPI FsInit(int PluginNr, tProgressProc pProgressProc, tLogProc pLogProc, tRequestProc pRequestProc)
{
    #pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    g_wfx.m_cb.ProgressProc = pProgressProc;
    g_wfx.m_cb.LogProc = pLogProc;
    g_wfx.m_cb.RequestProc = pRequestProc;
    LOGt("%s: plugin number = %d [%p,%p,%p] 0x%X", __func__, PluginNr, pProgressProc, pLogProc, pRequestProc, GetCurrentThreadId());
    return g_wfx.init(PluginNr);
}

WfxDllExport
int WINAPI FsInitW(int PluginNr, tProgressProcW pProgressProcW, tLogProcW pLogProcW, tRequestProcW pRequestProcW)
{
    #pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    g_wfx.m_cb.ProgressProcW = pProgressProcW;
    g_wfx.m_cb.LogProcW = pLogProcW;
    g_wfx.m_cb.RequestProcW = pRequestProcW;
    LOGt("%s: Plugin Number = %d [%p,%p,%p] 0x%X", __func__, PluginNr, pProgressProcW, pLogProcW, pRequestProcW, GetCurrentThreadId());
    return g_wfx.init(PluginNr);
}

WfxDllExport
void WINAPI FsSetDefaultParams(FsDefaultParamStruct * dps)
{
    #pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    wfx::ExCatcher exc(g_wfx);
    wfx::invoke(exc, 0, [&]{ return g_wfx.init(dps); });
}

WfxDllExport
void WINAPI FsSetCryptCallback(tCryptProc pCryptProc, int CryptoNr, int Flags)
{
    #pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    LOGt("%s: pCryptProc = %p, CryptoNr = 0x%08X, Flags = 0x%02X ", __func__, pCryptProc, CryptoNr, Flags);
    g_wfx.init(pCryptProc, CryptoNr, Flags);
}

WfxDllExport
BOOL WINAPI FsDisconnect(LPCSTR DisconnectRoot)
{
    #pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    wfx::ExCatcher exc(g_wfx);
    bool x = wfx::invoke(exc, false, [&] { return g_wfx.Disconnect(DisconnectRoot); });
    if (exc.is_active()) {
        return g_wfx.IsDisconnected() ? TRUE : FALSE;
    }
    return (BOOL)x;
}

WfxDllExport
HANDLE WINAPI FsFindFirstW(LPCWSTR Path, LPWIN32_FIND_DATAW FindData)
{
    #pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    wfx::ExCatcher exc(g_wfx);
    HANDLE eval = INVALID_HANDLE_VALUE;
    return wfx::invoke(exc, eval, [&] { return g_wfx.FindFirst(Path, FindData); });
}

WfxDllExport
HANDLE WINAPI FsFindFirst(LPCSTR Path, LPWIN32_FIND_DATAA FindData)
{
    #pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    LOGw("%s: <NOT-SUPPORTED>", __func__);
    return nullptr;
}

WfxDllExport
BOOL WINAPI FsFindNextW(HANDLE Hdl, LPWIN32_FIND_DATAW FindData)
{
    #pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    wfx::ExCatcher exc(g_wfx);
    return wfx::invoke(exc, false, [&] { return g_wfx.FindNext(Hdl, FindData); });
}

WfxDllExport
BOOL WINAPI FsFindNext(HANDLE Hdl, LPWIN32_FIND_DATAA FindData)
{
    #pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    LOGw("%s: <NOT-SUPPORTED>", __func__);
    return FALSE;
}

WfxDllExport
int WINAPI FsFindClose(HANDLE Hdl)
{
    #pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    wfx::ExCatcher exc(g_wfx);
    return wfx::invoke(exc, 0, [&] { return g_wfx.FindClose(Hdl); });
}

WfxDllExport
BOOL WINAPI FsMkDirW(LPCWSTR Path)
{
    #pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    wfx::ExCatcher exc(g_wfx);
    return wfx::invoke(exc, false, [&] { return g_wfx.MkDir(Path); });
}

WfxDllExport
BOOL WINAPI FsMkDir(LPCSTR Path)
{
    #pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    LOGw("%s: <NOT-SUPPORTED>", __func__);
    return FALSE;
}

WfxDllExport
int WINAPI FsExecuteFileW(HWND MainWin, LPWSTR RemoteName, LPCWSTR Verb)
{
    #pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    wfx::Exec eval = wfx::Exec::Error;
    wfx::ExCatcher exc(g_wfx);
    wfx::Exec rc = wfx::invoke(exc, eval, [&] { return g_wfx.ExecuteFile(eval, MainWin, RemoteName, Verb); });
    return exc.is_active() ? (int)eval : (int)rc;
}

WfxDllExport
int WINAPI FsExecuteFile(HWND MainWin, LPSTR RemoteName, LPCSTR Verb)
{
    #pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    LOGw("%s: <NOT-SUPPORTED>", __func__);
    return (int)wfx::Exec::Error;
}

WfxDllExport
int WINAPI FsRenMovFileW(LPCWSTR OldName, LPCWSTR NewName, BOOL Move, BOOL OverWrite, wfx::RemoteFileInfo * ri)
{
    #pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    wfx::File eval = wfx::File::NotFound;
    wfx::ExCatcher exc(g_wfx);
    wfx::File rc = wfx::invoke(exc, eval, [&] { return g_wfx.RenMovFile(OldName, NewName, !!Move, !!OverWrite, ri); });
    return (int)rc;
}

WfxDllExport
int WINAPI FsRenMovFile(LPCSTR OldName, LPCSTR NewName, BOOL Move, BOOL OverWrite, wfx::RemoteFileInfo * ri)
{
    #pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    LOGw("%s: <NOT-SUPPORTED>", __func__);
    return (int)wfx::File::NotFound;
}

WfxDllExport
int WINAPI FsGetFileW(LPCWSTR RemoteName, LPWSTR LocalName, int CopyFlags, wfx::RemoteFileInfo * ri)
{
    #pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    wfx::File eval = wfx::File::NotFound;
    wfx::ExCatcher exc(g_wfx);
    wfx::File rc = wfx::invoke(exc, eval, [&] { return g_wfx.GetFile(eval, RemoteName, LocalName, (wfx::CopyFlags)CopyFlags, ri); });
    return (int)rc;
}

WfxDllExport
int WINAPI FsGetFile(LPCSTR RemoteName, LPSTR LocalName, int CopyFlags, wfx::RemoteFileInfo * ri)
{
    #pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    LOGw("%s: <NOT-SUPPORTED>", __func__);
    return (int)wfx::File::NotFound;
}

WfxDllExport
int WINAPI FsPutFileW(LPCWSTR LocalName, LPCWSTR RemoteName, int CopyFlags)
{
    #pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    wfx::File eval = wfx::File::NotFound;
    wfx::ExCatcher exc(g_wfx);
    wfx::File rc = wfx::invoke(exc, eval, [&] { return g_wfx.PutFile(LocalName, RemoteName, (wfx::CopyFlags)CopyFlags); });
    return (int)rc;
}

WfxDllExport
int WINAPI FsPutFile(LPCSTR LocalName, LPCSTR RemoteName, int CopyFlags)
{
    #pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    LOGw("%s: <NOT-SUPPORTED>", __func__);
    return (int)wfx::File::NotFound;
}

WfxDllExport
BOOL WINAPI FsDeleteFileW(LPCWSTR RemoteName)
{
    #pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    wfx::ExCatcher exc(g_wfx);
    return wfx::invoke(exc, false, [&] { return g_wfx.DeleteFile(RemoteName); });
}

WfxDllExport
BOOL WINAPI FsDeleteFile(LPCSTR RemoteName)
{
    #pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    LOGw("%s: <NOT-SUPPORTED>", __func__);
    return FALSE;
}

