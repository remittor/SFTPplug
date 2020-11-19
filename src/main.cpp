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
    bool x = wfx::invoke(exc, false, [&] { return g_wfx.disconnect(DisconnectRoot); });
    if (exc.is_active()) {
        return g_wfx.IsDisconnected() ? TRUE : FALSE;
    }
    return (BOOL)x;
}

