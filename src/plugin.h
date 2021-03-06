#pragma once

#include "utils.h"
#include "sftpfunc.h"
#include "res/resource.h"
#include <vector>

#ifdef DeleteFile
#undef DeleteFile
#endif

namespace wfx {

static const char defininame[]   = "sftpplug.ini";
static const char templatefile[] = "sftpplug.tpl";
static const char pluginname[]   = "SFTP";
static const char defrootname[]  = "Secure FTP";


struct tLastFindStuct {
    LPVOID       sftpdataptr = nullptr;    /* LIBSSH2_SFTP_HANDLE or SCP_DATA */
    SERVERID     serverid = nullptr;
    SERVERHANDLE rootfindhandle = nullptr;
    bool         rootfindfirst = false;
};
typedef struct tLastFindStuct   tLastFindStuct;
typedef struct tLastFindStuct  *pLastFindStuct;


class Plugin : bst::NonCopyable
{
public:
    Plugin() noexcept = default;

    ~Plugin()
    {
        destroy();
    }

    int init(HMODULE lib_addr, DWORD thread_id) noexcept;
    int init(int PluginNumber) noexcept;
    int init(FsDefaultParamStruct * dps);  // <== general init func !!!
    int init(tCryptProc pCryptProc, int CryptoNr, CryptFlags Flags) noexcept;
    int destroy();

    bool Disconnect(LPCSTR DisconnectRoot);

    HANDLE FindFirst(LPCWSTR Path, LPWIN32_FIND_DATAW FindData);
    bool FindNext(HANDLE Hdl, LPWIN32_FIND_DATAW FindData);
    int FindClose(HANDLE Hdl);

    bool MkDir(LPCWSTR Path);
    Exec ExecuteFile(Exec & eval, HWND MainWin, LPWSTR RemoteName, LPCWSTR Verb);
    File RenMovFile(LPCWSTR OldName, LPCWSTR NewName, bool Move, bool OverWrite, RemoteFileInfo * ri);
    File GetFile(File & eval, LPCWSTR RemoteName, LPWSTR LocalName, CopyFlags flags, RemoteFileInfo * ri);
    File PutFile(LPCWSTR LocalName, LPCWSTR RemoteName, CopyFlags flags);
    bool DeleteFile(LPCWSTR RemoteName);
    bool RemoveDir(LPCWSTR RemoteName);
    bool SetAttr(LPCWSTR RemoteName, int NewAttr);
    bool SetTime(LPCWSTR RemoteName, LPFILETIME CreationTime, LPFILETIME LastAccessTime, LPFILETIME LastWriteTime);

    bool StatusInfo(LPCWSTR RemoteDir, OperStatus InfoStartEnd, OpStatus InfoOperation);
    Icon ExtractCustomIcon(LPCWSTR RemoteName, IconFlags ExtractFlags, HICON * TheIcon);
    HashFlags ServerSupportsChecksums(LPCWSTR RemoteName);
    HANDLE StartFileChecksum(HashFlags ChecksumType, LPCWSTR RemoteName);
    int GetFileChecksumResult(bool WantResult, HANDLE ChecksumHandle, LPCWSTR RemoteName, LPSTR checksum, int maxlen);

    UINT get_main_thread_id() { return m_main_thread_id; }

public:
    DWORD           m_main_thread_id = 0;
    HMODULE         m_module = nullptr;
    bool            m_inited = false;

    bst::str        m_inifilename;

    bool            m_disablereading = false;   // disable reading of subdirs to delete whole drives
    bool            m_freportconnect = true;    // report connect to caller only on first connect
    bool            m_CryptCheckPass = false;   // check 'store password encrypted' by default

    int             m_PluginNumber = 0;
    int             m_CryptoNumber = 0;

    struct {
        tProgressProc  ProgressProc = nullptr;
        tProgressProcW ProgressProcW = nullptr;
        tLogProc       LogProc = nullptr;
        tLogProcW      LogProcW = nullptr;
        tRequestProc   RequestProc = nullptr;
        tRequestProcW  RequestProcW = nullptr;
        tCryptProc     CryptProc = nullptr;
    } m_cb;  /* callbacks */

    size_t m_res_str_number = 0;
    std::vector<bst::str>  m_res_str;
    std::vector<bst::wstr> m_res_wstr;
    
    int load_resources(bool forced = false);
    int clear_res_strings();
    const bst::str & get_resA(size_t rid);
    const bst::wstr & get_resW(size_t rid);
    const bst::str & get_f7newconnection() { return get_resA(IDS_F7NEW); }
    const bst::wstr & get_f7newconnectionW() { return get_resW(IDS_F7NEW); }
    const bst::str & get_quickconnect() { return get_resA(IDS_QUICKCONNECT); }
    const bst::wstr & get_quickconnectW() { return get_resW(IDS_QUICKCONNECT); }

    bool IsMainThread() noexcept { return GetCurrentThreadId() == m_main_thread_id; }
    bool IsDisconnected() noexcept { return true; }   /* FIXME: !!!! */
    HINSTANCE get_HInstance() { return (HINSTANCE)m_module; }

    bool RequestProc(RT RequestType, bst::c_str & CustomTitle, bst::c_str & CustomText, bst::sfn * ReturnedText = nullptr);
    bool RequestProc(RT RequestType, bst::c_wstr & CustomTitle, bst::c_wstr & CustomText, bst::wsfn * ReturnedText = nullptr);
    bool RequestUserName(bst::c_str & title, bst::sfn & username);
    bool RequestPassword(bst::c_str & title, bst::sfn & password, bst::c_str & text);
    bool RequestPassword(bst::c_str & title, bst::sfn & password, size_t rid = 0);
    bool RequestPassword2(bst::c_str & title, bst::sfn & password);
    bool RequestCodePage(int & cp);
    bool RequestMsgOk(bst::c_str & title, bst::c_str & text);
    bool RequestMsgYesNo(bst::c_str & title, bst::c_str & text);

    void LogMessageEx(bool err, MsgType mt, size_t rid, LPCSTR fmtstr, ...);
    void LogMessageEx(bool err, MsgType mt, size_t rid, LPCWSTR fmtstr, ...);
    BST_ARGS void LogMsg(size_t rid, bst::c_str & fmt, Args...args);
    BST_ARGS void LogMsg(size_t rid, bst::c_wstr & fmt, Args...args);
    BST_ARGS void LogErr(size_t rid, bst::c_str & fmt, Args...args);
    BST_ARGS void LogErr(size_t rid, bst::c_wstr & fmt, Args...args);

    TaskStatus ProgressProc(bst::c_str & SourceName, bst::c_str & TargetName, int PercentDone);
    TaskStatus ProgressProc(bst::c_wstr & SourceName, bst::c_wstr & TargetName, int PercentDone);

    bool CryptPassword(CryptPass mode, bst::c_str & ConnectionName, bst::c_str & Password);
    bool PasswordLoad(bst::c_str & ConnectionName, bst::sfn & Password, bool no_ui = false);
    bool PasswordSave(bst::c_str & ConnectionName, bst::c_str & Password);
    bool PasswordDelete(bst::c_str & ConnectionName);
    bool PasswordCopy(bst::c_str & OldName, bst::c_str & NewName, bool move = false);

    size_t GetDisplayNameFromPath(bst::c_str & Path, bst::sfn & DisplayName);
    size_t GetDisplayNameFromPath(bst::c_wstr & Path, bst::sfn & DisplayName);
    pConnectSettings GetServerIdFromPath(bst::c_wstr & Path, bst::wsfp & RelativePath);
    pConnectSettings GetServerIdFromPath(bst::c_wstr & Path);

    //wfx::cfg      m_cfg;
    //wfx::inicfg   m_inicfg;

public:

protected:

};


BST_ARGS void Plugin::LogMsg(size_t rid, bst::c_str & fmt, Args...args)
{
    LogMessageEx(false, MsgType::Details, rid, fmt.c_str(), args...);
}

BST_ARGS void Plugin::LogMsg(size_t rid, bst::c_wstr & fmt, Args...args)
{
    LogMessageEx(false, MsgType::Details, rid, fmt.c_str(), args...);
}

BST_ARGS void Plugin::LogErr(size_t rid, bst::c_str & fmt, Args...args)
{
    LogMessageEx(true, MsgType::Details, rid, fmt.c_str(), args...);
}

BST_ARGS void Plugin::LogErr(size_t rid, bst::c_wstr & fmt, Args...args)
{
    LogMessageEx(true, MsgType::Details, rid, fmt.c_str(), args...);
}


} /* namespace */

extern wfx::Plugin g_wfx;  /* FIXME: remove! Because all classes must have a link to this object */
