#include "plugin.h"
#include "sftpplug.h"
#include <stdlib.h>
#include "utils.h"
#include "res/resource.h"
#include "sftpfunc.h"
#include "multiserver.h"
#include "cunicode.h"

namespace wfx {

int Plugin::init(HMODULE lib_addr, DWORD thread_id)	noexcept
{
    m_module = lib_addr;
    m_main_thread_id = thread_id;
    ::hinst = (HINSTANCE)lib_addr;
    return 0;
}

int Plugin::init(int PluginNumber) noexcept
{
    m_PluginNumber = PluginNumber;
    //LOGt("%s: thread ID = 0x%X", __func__, GetCurrentThreadId());

    ::ProgressProc = m_cb.ProgressProc;
    ::LogProc = m_cb.LogProc;
    ::RequestProc = m_cb.RequestProc;

    ::ProgressProcW = m_cb.ProgressProcW;
    ::LogProcW = m_cb.LogProcW;
    ::RequestProcW = m_cb.RequestProcW;

    ::PluginNumber = m_PluginNumber;
    ::mainthreadid = GetCurrentThreadId();
    return 0;
}

int Plugin::init(FsDefaultParamStruct * dps)
{
    ::InitMultiServer();

    m_inifilename = dps->DefaultIniName;
    size_t p = m_inifilename.rfind('\\');
    m_inifilename.resize((p == bst::npos) ? 0 : p + 1);
    m_inifilename.append(wfx::defininame);
    LOGn("%s: ini = '%s'", __func__, m_inifilename.c_str());

    strlcpy( ::inifilename, m_inifilename.c_str(), _countof(::inifilename));

    // copy ini template from plugin dir to ini location if it exists!
    bst::filename_a templatename;
    DWORD len = GetModuleFileNameA(hinst, templatename.data(), templatename.capacity());
    if (len > 0) {
        templatename.fix_length();
        size_t p = templatename.rfind('\\');
        if (p != bst::npos) {
            templatename.resize(p + 1);
            templatename.append(wfx::templatefile);
            CopyFileA(templatename.c_str(), m_inifilename.c_str(), TRUE);  // only copy if target doesn't exist
        }
    }

    //hr = m_inicfg.init(m_module);
    //if (hr == 0) {
    //    m_inicfg.copy(m_cfg);
    //}

    load_resources();

    m_inited = true;
    LOGn("%s: plugin inited!", __func__);
    return 0;
}

int Plugin::destroy()
{
    return 0;
}

int Plugin::init(tCryptProc pCryptProc, int CryptoNr, CryptFlags Flags) noexcept
{
    ::CryptProc = pCryptProc;
    ::CryptCheckPass = has_flag(Flags, CryptFlag::MasterPassSet);
    ::CryptoNumber = CryptoNr;

    m_cb.CryptProc = pCryptProc;
    m_CryptCheckPass = has_flag(Flags, CryptFlag::MasterPassSet);
    m_CryptoNumber = CryptoNr;

    return 0;
}

namespace resstr {
static const size_t per_section = 16;  /* https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-findresourceexa */
static const size_t max_section_id = USHRT_MAX / per_section;
}

BOOL CALLBACK EnumResNameProcA(HMODULE hModule, LPCSTR lpszType, LPSTR lpszName, LONG_PTR lParam) noexcept
{
    bool * sections = (bool *)lParam;
    if (sections && (size_t)lpszName <= resstr::max_section_id) {
        sections[(size_t)lpszName] = true;
    }
    return TRUE;
}

int Plugin::load_resources(bool forced)
{
    if (m_res_str_number > 0 && !forced)
        return 0;

    clear_res_strings();

    bool sections[resstr::max_section_id + 1] = {false};
    EnumResourceNamesA(m_module, RT_STRING, EnumResNameProcA, (LONG_PTR)sections);
    size_t max_sec_id = 0;
    size_t sec_count = 0;
    for (size_t i = 0; i < _countof(sections); i++) {
        if (sections[i]) {
            sec_count++;
            if (i > max_sec_id)
                max_sec_id = i;
        }
    }
    BST_THROW_IF(sec_count < 3, C, 100, "Resource read error");
    
    m_res_str.resize((max_sec_id + 1) * resstr::per_section);
    m_res_wstr.resize((max_sec_id + 1) * resstr::per_section);

    size_t rcount = 0;
    for (size_t i = 0; i < max_sec_id; i++) {
        if (sections[i + 1] == false)
            continue;
        for (size_t k = 0; k < resstr::per_section; k++) {
            size_t rid = (i * resstr::per_section) + k;
            union {
                LPCWSTR  wstr;
                wchar_t  bufw[8];
            } res;
            int len = LoadStringW((HINSTANCE)m_module, (UINT)rid, res.bufw, 0);
            if (len > 0 && res.wstr) {
                bst::wstr & wstr = m_res_wstr[rid];
                wstr.assign(res.wstr, (size_t)len);
                bst::str & str = m_res_str[rid];
                str.assign(CP_ACP, res.wstr, (size_t)len);
                //LOGt("%06Id(%03d) = '%s'", rid, len, m_res_str[rid].c_str());
                rcount++;
            }
        }
    }
    BST_THROW_IF(rcount < 10, C, 111, "Resource read error");
    //BST_THROW(C, 100, "Resource read error (TEST)");   // TEST
    //int * pp = nullptr;   // TEST
    //*pp = 1;              // TEST

    strlcpy( ::s_f7newconnection, get_f7newconnection().c_str(), _countof(::s_f7newconnection));
    wcslcpy( ::s_f7newconnectionW, get_f7newconnectionW().c_str(), _countof(::s_f7newconnectionW));

    strlcpy( ::s_quickconnect, get_quickconnect().c_str(), _countof(::s_quickconnect));
    wcslcpy( ::s_quickconnectW, get_quickconnectW().c_str(), _countof(::s_quickconnectW));

    m_res_str_number = rcount;
    return 0;
}

int Plugin::clear_res_strings()
{
    size_t size;
    m_res_str_number = 0;
    size = m_res_str.size();
    for (size_t i = 0; i < size; i++)
        m_res_str[i].destroy();
    size = m_res_wstr.size();
    for (size_t i = 0; i < size; i++)
        m_res_wstr[i].destroy();
    return 0;
}

const bst::str & Plugin::get_resA(size_t rid)
{
    BST_THROW_IF(rid >= m_res_str.size(), C, 100, "Incorrect resource id = %Id", rid);
    BST_THROW_IF(m_res_str[rid].is_null(), C, 101, "Incorrect resource id = %Id", rid);
    return m_res_str[rid];
}

const bst::wstr & Plugin::get_resW(size_t rid)
{
    BST_THROW_IF(rid >= m_res_wstr.size(), C, 102, "Incorrect resource id = %Id", rid);
    BST_THROW_IF(m_res_wstr[rid].is_null(), C, 103, "Incorrect resource id = %Id", rid);
    return m_res_wstr[rid];
}

bool Plugin::RequestProc(RT RequestType, bst::c_str & CustomTitle, bst::c_str & CustomText, bst::sfn * ReturnedText)
{
    BST_THROW_IF(!m_cb.RequestProc, C, 5001, "RequestProc is null");
    char ret_buf[4] = { 0 };
    LPSTR ret_txt = ReturnedText ? ReturnedText->data() : ret_buf;
    size_t maxlen = ReturnedText ? ReturnedText->capacity() : _countof(ret_buf) - 1;
    LPCSTR txt = (CustomText.length() == 0) ? nullptr : CustomText.c_str();
    BOOL x = m_cb.RequestProc(m_PluginNumber, (int)RequestType, CustomTitle.c_str(), txt, ret_txt, (int)maxlen);
    if (ReturnedText)
        ReturnedText->fix_length();
    return (x == TRUE) ? true : false;
}

bool Plugin::RequestProc(RT RequestType, bst::c_wstr & CustomTitle, bst::c_wstr & CustomText, bst::wsfn * ReturnedText)
{
    BST_THROW_IF(!m_cb.RequestProcW, C, 5002, "RequestProc is null");
    WCHAR ret_buf[4] = { 0 };
    LPWSTR ret_txt = ReturnedText ? ReturnedText->data() : ret_buf;
    size_t maxlen = ReturnedText ? ReturnedText->capacity() : _countof(ret_buf) - 1;
    LPCWSTR txt = (CustomText.length() == 0) ? nullptr : CustomText.c_str();
    BOOL x = m_cb.RequestProcW(m_PluginNumber, (int)RequestType, CustomTitle.c_str(), txt, ret_txt, (int)maxlen);
    if (ReturnedText)
        ReturnedText->fix_length();
    return (x == TRUE) ? true : false;
}

bool Plugin::RequestUserName(bst::c_str & title, bst::sfn & username)
{
    return RequestProc(RT::UserName, title, nullptr, &username);
}

bool Plugin::RequestPassword(bst::c_str & title, bst::sfn & password, bst::c_str & text)
{
    return RequestProc(RT::Password, title, text, &password);
}

bool Plugin::RequestPassword(bst::c_str & title, bst::sfn & password, size_t rid)
{    
    return RequestProc(RT::Password, title, rid ? get_resA(rid).c_str() : "", &password);
}

bool Plugin::RequestPassword2(bst::c_str & title, bst::sfn & password)
{
    return RequestProc(RT::PasswordFirewall, title, title, &password);
}

bool Plugin::RequestCodePage(int & cp)
{
    bst::sfn codepage;
    bool x = RequestProc(RT::Other, "Code page", "Code page (e.g. 28591):", &codepage);
    if (x) {
        int val = codepage.atoi(-1);
        if (val >= 0) {
            cp = val;
            return true;
        }
    }
    return false;
}

bool Plugin::RequestMsgOk(bst::c_str & title, bst::c_str & text)
{
    return RequestProc(RT::MsgOk, title, text, nullptr);
}

bool Plugin::RequestMsgYesNo(bst::c_str & title, bst::c_str & text)
{
    return RequestProc(RT::MsgYesNo, title, text, nullptr);
}

void Plugin::LogMessageEx(bool err, MsgType mt, size_t rid, LPCSTR fmtstr, ...)
{
    BST_THROW_IF(!m_cb.LogProc, C, 5011, "LogProc is null");
    bst::sfp buf;
    bst::sfp fmt;
    if (rid)
        fmt.append(get_resA(rid));
    if (fmtstr)
        fmt.append(fmtstr);
    va_list args;
    va_start(args, fmtstr);
    int len = _vsnprintf(buf.data(), buf.capacity(), fmt.c_str(), args);
    if (len < 0) {
        buf = "<INCORRECT-INPUT-DATA> ";
        buf += fmt;
    } else {
        buf.resize(len);
        buf.fix_length();
    }
    m_cb.LogProc(m_PluginNumber, (int)mt, buf.c_str());
    if (err)
        RequestMsgOk("SFTP Error", buf.c_str());
}

void Plugin::LogMessageEx(bool err, MsgType mt, size_t rid, LPCWSTR fmtstr, ...)
{
    BST_THROW_IF(!m_cb.LogProcW, C, 5012, "LogProc is null");
    bst::wsfp buf;
    bst::wsfp fmt;
    if (rid)
        fmt.append(get_resW(rid));
    if (fmtstr)
        fmt.append(fmtstr);
    va_list args;
    va_start(args, fmt);
    int len = _vsnwprintf(buf.data(), buf.capacity(), fmt.c_str(), args);
    if (len < 0) {
        buf = L"<INCORRECT-INPUT-DATA> ";
        buf += fmt;
    } else {
        buf.resize(len);
        buf.fix_length();
    }
    m_cb.LogProcW(m_PluginNumber, (int)mt, buf.c_str());
    if (err)
        RequestProc(RT::MsgOk, L"SFTP Error", buf.c_str());
}

TaskStatus Plugin::ProgressProc(bst::c_str & SourceName, bst::c_str & TargetName, int PercentDone)
{
    BST_THROW_IF(!m_cb.ProgressProc, C, 7001, "ProgressProc is null");
    int x = m_cb.ProgressProc(m_PluginNumber, SourceName.c_str(), TargetName.c_str(), PercentDone);
    return (x == 1) ? TaskStatus::Aborted : TaskStatus::Continue;
}

TaskStatus Plugin::ProgressProc(bst::c_wstr & SourceName, bst::c_wstr & TargetName, int PercentDone)
{
    BST_THROW_IF(!m_cb.ProgressProcW, C, 7002, "ProgressProc is null");
    int x = m_cb.ProgressProcW(m_PluginNumber, SourceName.c_str(), TargetName.c_str(), PercentDone);
    return (x == 1) ? TaskStatus::Aborted : TaskStatus::Continue;
}

bool Plugin::CryptPassword(CryptPass mode, bst::c_str & ConnectionName, bst::c_str & Password)
{
    BST_THROW_IF(mode == CryptPass::Load || mode == CryptPass::LoadNoUI, C, 3001, "Incorrect argument");
    if (!m_cb.CryptProc)
        return false;
    int rc = m_cb.CryptProc(m_PluginNumber, m_CryptoNumber, (int)mode, ConnectionName.c_str(), (LPSTR)Password.c_str(), 0);
    return (rc == (int)File::Ok) ? true : false;
}

bool Plugin::PasswordLoad(bst::c_str & ConnectionName, bst::sfn & Password, bool no_ui)
{
    if (!m_cb.CryptProc)
        return false;
    CryptPass mode = no_ui ? CryptPass::LoadNoUI : CryptPass::Load;
    int rc = m_cb.CryptProc(m_PluginNumber, m_CryptoNumber, (int)mode, ConnectionName.c_str(), Password.data(), (int)Password.max_len);
    Password.fix_length();
    return (rc == (int)File::Ok) ? true : false;
}

bool Plugin::PasswordSave(bst::c_str & ConnectionName, bst::c_str & Password)
{
    return CryptPassword(CryptPass::Save, ConnectionName, Password);
}

bool Plugin::PasswordDelete(bst::c_str & ConnectionName)
{
    return CryptPassword(CryptPass::Delete, ConnectionName, nullptr);
}

bool Plugin::PasswordCopy(bst::c_str & OldName, bst::c_str & NewName, bool move)
{
    return CryptPassword(move ? CryptPass::Move : CryptPass::Copy, OldName, NewName);
}

bool Plugin::Disconnect(LPCSTR DisconnectRoot)
{
    LOGt("%s: '%s' ", __func__, DisconnectRoot);
    bst::sfn DisplayName;
    GetDisplayNameFromPath(DisconnectRoot, DisplayName);
    SERVERID serverid = GetServerIdFromName(DisplayName.c_str(), GetCurrentThreadId());
    if (serverid) {
        LogMessageEx(false, MsgType::Disconnect, 0, "DISCONNECT \\%s", DisplayName.c_str());
        SftpCloseConnection(serverid);
        SetServerIdForName(DisplayName.c_str(), NULL); // this frees it too!
    }
    return true;
}

size_t Plugin::GetDisplayNameFromPath(bst::c_str & Path, bst::sfn & DisplayName)
{
    DisplayName.clear();
    LPCSTR p = Path.c_str();
    while (*p == '\\' || *p == '/')
        p++;
    if (*p) {
        LPCSTR s = p;
        while (*p && *p != '\\' && *p != '/')
            p++;
        if (p > s) {
            DisplayName.assign(s, (size_t)(p - s));
            return (size_t)(p - Path.c_str());
        }
    }
    return 0;
}

size_t Plugin::GetDisplayNameFromPath(bst::c_wstr & Path, bst::sfn & DisplayName)
{
    DisplayName.clear();
    LPCWSTR p = Path.c_str();
    while (*p == L'\\' || *p == L'/')
        p++;
    if (*p) {
        LPCWSTR s = p;
        while (*p && *p != L'\\' && *p != L'/')
            p++;
        if (p > s) {
            DisplayName.assign(CP_ACP, s, (size_t)(p - s));
            return (size_t)(p - Path.c_str());
        }
    }
    return 0;
}

pConnectSettings Plugin::GetServerIdFromPath(bst::c_wstr & Path, bst::wsfp & RelativePath)
{
    RelativePath = L"\\";
    bst::sfn DisplayName;
    size_t pp = GetDisplayNameFromPath(Path, DisplayName);
    SERVERID serverid = GetServerIdFromName(DisplayName.c_str(), GetCurrentThreadId());
    if (serverid && pp > 0) {
        RelativePath.assign(Path.c_str() + pp);
        if (RelativePath.empty())
            RelativePath = L"\\";
    }
    return (pConnectSettings)serverid;
}

pConnectSettings Plugin::GetServerIdFromPath(bst::c_wstr & Path)
{
    bst::sfn DisplayName;
    size_t pp = GetDisplayNameFromPath(Path, DisplayName);
    return (pConnectSettings) GetServerIdFromName(DisplayName.c_str(), GetCurrentThreadId());
}

HANDLE Plugin::FindFirst(LPCWSTR Path, LPWIN32_FIND_DATAW FindData)
{
    int hr = ERROR_SUCCESS;
    WLOGt(L"%S: path = '%s' ", __func__, Path);
    bst::wsfp remotedir;
    bst::sfn DisplayName;
    pLastFindStuct lf;

    if (wcscmp(Path, L"\\") == 0) {  // in the root!
        LoadServersFromIni(m_inifilename.c_str(), get_quickconnect().c_str());
        memset(FindData, 0, sizeof(WIN32_FIND_DATAW));
        get_f7newconnectionW().copy(FindData->cFileName, countof(FindData->cFileName) - 1);
        FindData->dwFileAttributes = 0;
        SetInt64ToFileTime(&FindData->ftLastWriteTime, TimeUnknown);
        FindData->nFileSizeLow = (DWORD)get_resA(IDS_HELPTEXT).length();
        lf = new tLastFindStuct();
        lf->rootfindfirst = true;
        return (HANDLE)lf;
    }

    SERVERID serverid = NULL;
    SERVERID new_serverid = NULL;
    LPVOID sftpdataptr = NULL;
    {
        SCOPE_FAILURE {
            if (new_serverid) {  // initial connect failed
                SftpCloseConnection(new_serverid);
                SetServerIdForName(DisplayName.c_str(), NULL); // this frees it too!
                freportconnect = false;
                SetLastError(ERROR_PATH_NOT_FOUND);
            }
        };

        // load server list if user connects directly via URL
        LoadServersFromIni(m_inifilename.c_str(), get_quickconnect().c_str());
        // only disable the reading within a server!
        if (disablereading && g_wfx.IsMainThread()) {
            SetLastError(ERROR_NO_MORE_FILES);
            return INVALID_HANDLE_VALUE;
        }
        GetDisplayNameFromPath(Path, DisplayName);
        serverid = GetServerIdFromName(DisplayName.c_str(), GetCurrentThreadId());
        if (serverid == nullptr) {
            new_serverid = SftpConnectToServer(DisplayName.c_str(), m_inifilename.c_str(), NULL);
            if (!new_serverid) {
                SetLastError(ERROR_PATH_NOT_FOUND);
                return INVALID_HANDLE_VALUE;
            }
            serverid = new_serverid;
            SetServerIdForName(DisplayName.c_str(), serverid);
        }
        memset(FindData, 0, sizeof(WIN32_FIND_DATAW));

        GetServerIdFromPath(Path, remotedir);

        // Retrieve the directory
        bool ok = (SFTP_OK == SftpFindFirstFileW(serverid, remotedir.c_str(), &sftpdataptr));

        if (remotedir.length() <= 1 || wcscmp(remotedir.c_str() + 1, L"home") == 0) {    // root -> add ~ link to home dir
            SYSTEMTIME st;
            GetSystemTime(&st);
            SystemTimeToFileTime(&st, &FindData->ftLastWriteTime);
            wcslcpy(FindData->cFileName, L"~", countof(FindData->cFileName) - 1);
            FindData->dwFileAttributes = AttrUnixMode;
            FindData->dwReserved0 = LIBSSH2_SFTP_S_IFLNK | 0555; // attributes and format mask  /* FIXME: magic number! */
            lf = new tLastFindStuct();
            if (ok)
                lf->sftpdataptr = sftpdataptr;
            lf->serverid = serverid;
            return (HANDLE)lf;
        }
        BST_THROW_IF(!ok, U, 40010, "Failure on init connection");
    }

    SCOPE_FAILURE {
        SftpFindClose(serverid, sftpdataptr);
        SetLastError(ERROR_NO_MORE_FILES);
    };
    int rc = SftpFindNextFileW(serverid, sftpdataptr, FindData);
    BST_THROW_IF(rc != SFTP_OK, U, 40020, "Failure on init connection");

    lf = new tLastFindStuct();
    lf->sftpdataptr = sftpdataptr;
    lf->serverid = serverid;
    return (HANDLE)lf;
}

bool Plugin::FindNext(HANDLE Hdl, LPWIN32_FIND_DATAW FindData)
{
    bst::sfn name;

    if (Hdl == (HANDLE)1)    /* FIXME: need explanatory comment */
        return false;

    pLastFindStuct lf = (pLastFindStuct)Hdl;
    if (!lf || lf == INVALID_HANDLE_VALUE)
        return false;

    if (lf->rootfindfirst) {
        SERVERHANDLE hdl = FindFirstServer(name.data(), name.capacity());
        if (!hdl)
            return false;
        name.fix_length();
        awlcopy(FindData->cFileName, name.c_str(), countof(FindData->cFileName)-1);
        lf->rootfindhandle = hdl;
        lf->rootfindfirst = false;
        SetInt64ToFileTime(&FindData->ftLastWriteTime, TimeUnknown);
        FindData->dwFileAttributes = AttrUnixMode;
        FindData->dwReserved0 = LIBSSH2_SFTP_S_IFLNK; // it's a link
        FindData->nFileSizeLow = 0;
        return true;
    }
    if (lf->rootfindhandle) {
        lf->rootfindhandle = FindNextServer(lf->rootfindhandle, name.data(), name.capacity());
        if (!lf->rootfindhandle)
            return false;
        name.fix_length();
        awlcopy(FindData->cFileName, name.c_str(), countof(FindData->cFileName)-1);
        FindData->dwFileAttributes = AttrUnixMode;
        FindData->dwReserved0 = LIBSSH2_SFTP_S_IFLNK; //it's a link
        return true;
    }
    if (lf->sftpdataptr) {
        int rc = SftpFindNextFileW(lf->serverid, lf->sftpdataptr, FindData);
        return (rc == SFTP_OK) ? true : false;
    }
    return false;
}

int Plugin::FindClose(HANDLE Hdl)
{
    if (!Hdl || Hdl == INVALID_HANDLE_VALUE)
        return 0;

    pLastFindStuct lf = (pLastFindStuct)Hdl;
    SCOPE_EXIT {
        lf->sftpdataptr = NULL;
        delete lf;
    };
    if (lf->sftpdataptr)
        SftpFindClose(lf->serverid, lf->sftpdataptr);

    return 0;
}

bool Plugin::MkDir(LPCWSTR Path)
{
    bst::wsfp remotedir;
    LPCWSTR p = wcschr(Path + 1, L'\\');
    if (p) {
        SERVERID serverid = GetServerIdFromPath(Path, remotedir);
        if (!serverid)
            return false;
        int rc = SftpCreateDirectoryW(serverid, remotedir.c_str());
        return (rc == SFTP_OK) ? true : false;
    }
    // new connection
    remotedir = Path + 1;
    if (!remotedir.iequal(get_quickconnectW()) && !remotedir.iequal(get_f7newconnectionW())) {
        bst::sfn DisplayName;
        size_t pp = GetDisplayNameFromPath(Path, DisplayName);    
        LoadServersFromIni(m_inifilename.c_str(), get_quickconnect().c_str());
        if (SftpConfigureServer(DisplayName.c_str(), m_inifilename.c_str())) {
            /* reload config */
            LoadServersFromIni(m_inifilename.c_str(), get_quickconnect().c_str());
            return true;
        }
    }
    return false;
}

static bool is_full_name(LPCSTR path)
{
    return path && path[0] && path[1] && strchr(path + 1, '\\');
}

static bool is_full_name(LPCWSTR path)
{
    return path && path[0] && path[1] && wcschr(path + 1, L'\\');
}

static LPWSTR cut_srv_name(LPWSTR path)
{
    if (path && path[0] && path[1]) {
        LPWSTR p = wcschr(path + 1, L'\\');
        if (p) {
            p[0] = 0;
            return path + 1;
        }
    }
    return NULL;
}

Exec Plugin::ExecuteFile(Exec & eval, HWND MainWin, LPWSTR RemoteName, LPCWSTR Verb)
{
    eval = Exec::Error;
    bst::sfp remoteserver;
    bst::wsfp remotedir;
    if (_wcsicmp(Verb, L"open") == 0) {   // follow symlink
        eval = Exec::YourSelf;
        if (is_full_name(RemoteName)) {
            SERVERID serverid = GetServerIdFromPath(RemoteName, remotedir);
            if (!serverid)
                return eval;
            if (!SftpLinkFolderTargetW(serverid, remotedir.data(), remotedir.capacity()))
                return eval;
            remotedir.fix_length();
            // now build the target name: server name followed by new path
            LPWSTR p = cut_srv_name(RemoteName);
            if (!p)
                return Exec::Error;
            // make sure that we can reach the path!!!
            wcslcat(RemoteName, remotedir.c_str(), wdirtypemax-1);
            ReplaceSlashByBackslashW(RemoteName);
            return Exec::SymLink;
        }
        if (_wcsicmp(RemoteName + 1, get_f7newconnectionW().c_str()) != 0) {
            LPWSTR p = RemoteName + wcslen(RemoteName);
            int pmaxlen = wdirtypemax - (size_t)(p - RemoteName) - 1;
            remoteserver.assign(CP_ACP, RemoteName + 1);
            SERVERID serverid = GetServerIdFromName(remoteserver.c_str(), GetCurrentThreadId());
            if (serverid) {
                SftpGetLastActivePathW(serverid, p, pmaxlen);
            } else {
                // Quick connect: We must connect here,  otherwise we
                // cannot switch to the subpath chosen by the user!
                if (remoteserver.iequal(get_quickconnect())) {
                    serverid = SftpConnectToServer(remoteserver.c_str(), m_inifilename.c_str(), NULL);
                    if (!serverid)
                        return Exec::Error;
                    SetServerIdForName(remoteserver.c_str(), serverid);
                    SftpGetLastActivePathW(serverid, p, pmaxlen);
                } else {
                    SftpGetServerBasePathW(RemoteName + 1, p, pmaxlen, inifilename);
                }
            }
            if (p[0] == 0)
                wcslcat(RemoteName, L"/", wdirtypemax-1);
            ReplaceSlashByBackslashW(RemoteName);
            return Exec::SymLink;
        }
        return eval;
    }
    if (_wcsicmp(Verb, L"properties") == 0) {
        if (RemoteName[1] && wcschr(RemoteName + 1, L'\\') == 0) {
            remoteserver.assign(CP_ACP, RemoteName + 1);
            if (!remoteserver.iequal(get_f7newconnection()) && !remoteserver.iequal(get_quickconnect())) {
                if (SftpConfigureServer(remoteserver.c_str(), inifilename)) {
                    LoadServersFromIni(inifilename, get_quickconnect().c_str());
                }
            }
        } else {
            bst::wsfp remotename;
            SERVERID serverid = GetServerIdFromPath(RemoteName, remotename);
            /* FIXME: check serverid with NULL */
            SftpShowPropertiesW(serverid, remotename.c_str());
        }
        return Exec::Ok;
    }
    if (_wcsnicmp(Verb, L"chmod ", 6) == 0) {
        if (RemoteName[1] && wcschr(RemoteName+1, '\\') != 0) {
            SERVERID serverid = GetServerIdFromPath(RemoteName, remotedir);
            /* FIXME: check serverid with NULL */
            if (SftpChmodW(serverid, remotedir.c_str(), Verb+6))
                return Exec::Ok;
        }
        return Exec::Error;
    }
    if (_wcsnicmp(Verb, L"quote ", 6) == 0) {
        if (wcsncmp(Verb + 6, L"cd ", 3) == 0) {
            // first get the start path within the plugin
            SERVERID serverid = GetServerIdFromPath(RemoteName, remotedir);
            /* FIXME: check serverid with NULL */
            remotedir.clear();
            if (Verb[9] != '\\' && Verb[9] != '/')     // relative path?
                remotedir.assign(L"\\");
            remotedir.append(Verb + 9);
            remotedir.replace(L'/', L'\\');
            LPWSTR p = cut_srv_name(RemoteName);
            if (!p)
                return Exec::Error;
            // make sure that we can reach the path!!!
            wcslcat(RemoteName, remotedir.c_str(), wdirtypemax - 1);
            ReplaceSlashByBackslashW(RemoteName);
            return Exec::SymLink;
        }
        if (is_full_name(RemoteName)) {
            SERVERID serverid = GetServerIdFromPath(RemoteName, remotedir);
            /* FIXME: check serverid with NULL */
            if (SftpQuoteCommand2W(serverid, remotedir.c_str(), Verb+6, NULL, 0) != 0)  /* FIXME: this function returned -1, 0, 1 */
                return Exec::Ok;
        }
        return Exec::Error;
    }
    if (_wcsnicmp(Verb, L"mode ", 5) == 0) {   // Binary/Text/Auto
        SftpSetTransferModeW(Verb+5);
        /* FIXME: return FS_EXEC_OK ??? */
    }
    return Exec::Error;
}

__forceinline
static void ResetLastPercent(pConnectSettings ConnectSettings)
{
    if (ConnectSettings)
        ConnectSettings->lastpercent = 0;
}

File Plugin::RenMovFile(LPCWSTR OldName, LPCWSTR NewName, bool Move, bool OverWrite, RemoteFileInfo * ri)
{
    bst::wsfp olddir;
    bst::wsfp newdir;

    // Rename or copy a server?
    LPCWSTR p1 = wcschr(OldName + 1, '\\');
    LPCWSTR p2 = wcschr(NewName + 1, '\\');
    if (p1 == NULL && p2 == NULL) {
        bst::sfn OldNameA;
        OldNameA.assign(CP_ACP, OldName + 1);
        bst::sfn NewNameA;
        NewNameA.assign(CP_ACP, NewName + 1);
        File rc = (File) CopyMoveServerInIni(OldNameA.c_str(), NewNameA.c_str(), Move, OverWrite, inifilename);
        if (rc == File::Ok) {
            PasswordCopy(OldNameA, NewNameA, Move);
            return File::Ok;
        }
        return (rc == File::Exists) ? File::Exists : File::NotFound;
    }

    pConnectSettings serverid1 = GetServerIdFromPath(OldName, olddir);
    pConnectSettings serverid2 = GetServerIdFromPath(NewName, newdir);

    // must be on same server!
    if (serverid1 != serverid2 || serverid1 == NULL)
        return File::NotFound;

    ResetLastPercent(serverid1);

    bool isdir = (ri->Attr & FILE_ATTRIBUTE_DIRECTORY) ? true : false;

    sftp::error rc = (sftp::error) SftpRenameMoveFileW(serverid1, olddir.c_str(), newdir.c_str(), Move, OverWrite, isdir);
    switch (rc) {
    case sftp::kOk:
        return File::Ok;
    case sftp::kExists:
        return File::Exists;
    }
    return File::NotFound;
}

static void RemoveInalidChars(LPSTR p)
{
    while (p[0]) {
        if ((UCHAR)p[0] < 32)
            p[0] = ' ';
        else if (p[0] == ':' || p[0] == '|' || p[0] == '*' || p[0] == '?' || p[0] == '\\' || p[0] == '/' || p[0] == '"')
            p[0] = '_';
        p++;
    }
}

static void RemoveInalidChars(LPWSTR p)
{
    while (p[0]) {
        if ((WORD)p[0] < 32)
            p[0] = L' ';
        else if (p[0] == L':' || p[0] == L'|' || p[0] == L'*' || p[0] == L'?' || p[0] == L'\\' || p[0] == L'/' || p[0] == L'"')
            p[0] = L'_';
        p++;
    }
}

File Plugin::GetFile(File & eval, LPCWSTR RemoteName, LPWSTR LocalName, CopyFlags flags, RemoteFileInfo * ri)
{
    eval = File::NotFound;
    bool OverWrite = has_flag(flags, CopyFlag::Overwrite);
    bool Resume = has_flag(flags, CopyFlag::Resume);
    bool Move = has_flag(flags, CopyFlag::Move);

    if (wcslen(RemoteName) < 3)
        return File::NotFound;

    LPWSTR p = wcsrchr(LocalName, '\\');
    if (p)
        RemoveInalidChars(p + 1);  // Changes the name passed in!

    bst::wsfp LocalNameEx = LocalName;
    LocalNameEx.make_path();

    if (wcscmp(RemoteName + 1, get_f7newconnectionW().c_str()) == 0) {
        eval = File::WriteError;
        const bst::str & txt = get_resA(IDS_HELPTEXT);
        DWORD dwAccess = GENERIC_WRITE;
        DWORD dwShareMode = FILE_SHARE_READ | FILE_SHARE_WRITE;
        DWORD dwDispos = OverWrite ? CREATE_ALWAYS : CREATE_NEW;
        DWORD dwFlags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN;
        HANDLE houtfile = CreateFileW(LocalNameEx.c_str(), dwAccess, dwShareMode, NULL, dwDispos, dwFlags, NULL);
        if (!houtfile || houtfile == INVALID_HANDLE_VALUE)
            return OverWrite ? File::Exists : File::WriteError;
        DWORD written;
        BOOL ret = WriteFile(houtfile, txt.c_str(), (DWORD)txt.size_bytes(), &written, NULL);
        CloseHandle(houtfile);
        return ret ? File::Ok : File::WriteError;
    }

    bst::wsfp remotedir;
    pConnectSettings serverid = GetServerIdFromPath(RemoteName, remotedir);
    if (serverid == NULL)
        return File::ReadError;

    ResetLastPercent(serverid);

    TaskStatus ts = ProgressProc(RemoteName, LocalName, 0);
    if (ts == TaskStatus::Aborted)
        return File::UserAbort;

    DWORD dwAttr = GetFileAttributesW(LocalNameEx.c_str());
    if (!OverWrite && !Resume && dwAttr != INVALID_FILE_ATTRIBUTES) {
        // Resume isn't possible because we cannot know
        // which <CR> characters were already in the original
        // file,  and which were added during the download
        bool TextMode = (serverid->unixlinebreaks == 1) && SftpDetermineTransferModeW(RemoteName);
        if (TextMode)
            return File::Exists;  // SFTP_FAILED
        return File::ExistsResumeAllowed;
    }
    if (OverWrite) {
        DeleteFileW(LocalNameEx.c_str());
    }

    eval = File::UserAbort;
    while (true) {  // auto-resume loop
        bool always_overwrite = true;
        int rc = SftpDownloadFileW(serverid, remotedir.c_str(), LocalName, always_overwrite, ri->Size64, &ri->LastWriteTime, Resume);
        switch ((sftp::error)rc) {
        case sftp::kOk:          return File::Ok;
        case sftp::kExists:      return File::Exists;
        case sftp::kReadFailed:  return File::ReadError;
        case sftp::kWriteFailed: return File::WriteError;
        case sftp::kAbort:       return File::UserAbort;
        case sftp::kPartial:     Resume = true; break;
        default: return File::Ok;
        }
    }
    return File::Ok;
}

File Plugin::PutFile(LPCWSTR LocalName, LPCWSTR RemoteName, CopyFlags flags)
{
    bool OverWrite = has_flag(flags, CopyFlag::Overwrite);
    bool Resume = has_flag(flags, CopyFlag::Resume);
    bool Move = has_flag(flags, CopyFlag::Move);

    // Auto-overwrites files -> return error if file exists
    if (has_any_flag(flags, CopyFlag::ExistsSameCase | CopyFlag::ExistsDifferentCase))
        if (!OverWrite && !Resume)
            return File::ExistsResumeAllowed;

    if (wcslen(RemoteName) < 3)
        return File::WriteError;

    TaskStatus ts = ProgressProc(LocalName, RemoteName, 0);
    if (ts == TaskStatus::Aborted)
        return File::UserAbort;

    bst::wsfp remotedir;
    pConnectSettings serverid = GetServerIdFromPath(RemoteName, remotedir);
    if (serverid == NULL)
        return File::ReadError;

    ResetLastPercent(serverid);

    bool setattr = !has_flag(flags, CopyFlag::ExistsSameCase);
    int rc = SftpUploadFileW(serverid, LocalName, remotedir.c_str(), Resume, setattr);
    switch ((sftp::error)rc) {
    case sftp::kOk:          return File::Ok;
    case sftp::kExists:      return SftpSupportsResume(serverid) ? File::ExistsResumeAllowed : File::Exists;
    case sftp::kReadFailed:  return File::ReadError;
    case sftp::kWriteFailed: return File::WriteError;
    case sftp::kAbort:       return File::UserAbort;
    }
    return File::NotFound;
}

bool Plugin::DeleteFile(LPCWSTR RemoteName)
{
    bst::wsfp remotedir;

    if (wcslen(RemoteName) < 3)
        return false;

    LPCWSTR p = wcschr(RemoteName+1, '\\');
    if (p) {
        pConnectSettings serverid = GetServerIdFromPath(RemoteName, remotedir);
        if (serverid)
            return false;
        ResetLastPercent(serverid);
        int rc = SftpDeleteFileW(serverid, remotedir.c_str(), false);
        return (rc == (int)sftp::kOk) ? true : false;
    }
    // delete server
    remotedir = RemoteName + 1;
    if (!remotedir.iequal(get_f7newconnectionW()) && !remotedir.iequal(get_quickconnectW())) {
        bst::sfn srvname;
        srvname.assign(CP_ACP, RemoteName + 1);
        if (DeleteServerFromIni(srvname.c_str(), inifilename)) {
            PasswordDelete(srvname);
            return true;
        }
    }
    return false;
}

bool Plugin::RemoveDir(LPCWSTR RemoteName)
{
    if (!is_full_name(RemoteName))
        return false;

    bst::wsfp remotedir;
    pConnectSettings serverid = GetServerIdFromPath(RemoteName, remotedir);
    if (serverid == NULL)
        return false;
    ResetLastPercent(serverid);
    int rc = SftpDeleteFileW(serverid, remotedir.c_str(), true);
    return (rc == (int)sftp::kOk) ? true : false;
}

bool Plugin::SetAttr(LPCWSTR RemoteName, int NewAttr)
{
    bst::wsfp remotedir;
    pConnectSettings serverid = GetServerIdFromPath(RemoteName, remotedir);
    if (serverid == NULL)
        return false;
    ResetLastPercent(serverid);
    bst::sfp remotedirA;
    remotedirA.assign(CP_ACP, remotedir.c_str());   /* FIXME: make SftpSetAttrW */
    int rc = SftpSetAttr(serverid, remotedirA.c_str(), NewAttr);
    return (rc == (int)sftp::kOk) ? true : false;
}

bool Plugin::SetTime(LPCWSTR RemoteName, LPFILETIME CreationTime, LPFILETIME LastAccessTime, LPFILETIME LastWriteTime)
{
    bst::wsfp remotedir;
    pConnectSettings serverid = GetServerIdFromPath(RemoteName, remotedir);
    if (serverid == NULL)
        return false;
    ResetLastPercent(serverid);
    int rc = SftpSetDateTimeW(serverid, remotedir.c_str(), LastWriteTime);
    return (rc == (int)sftp::kOk) ? true : false;
}

bool Plugin::StatusInfo(LPCWSTR RemoteDir, OperStatus InfoStartEnd, OpStatus InfoOperation)
{
    if (wcslen(RemoteDir) < 2)
        if (InfoOperation == OpStatus::Delete || InfoOperation == OpStatus::RenMovMulti)
            disablereading = (InfoStartEnd == OperStatus::Start) ? true : false;

    if (InfoOperation == OpStatus::GetMultiThread || InfoOperation == OpStatus::PutMultiThread) {
        bst::sfp RemoteDirA;
        RemoteDirA.assign(CP_ACP, RemoteDir);
        if (InfoStartEnd != OperStatus::Start) {
            Disconnect(RemoteDirA.c_str());
            return true;
        }
        bst::sfn DisplayName;
        LPSTR oldpass = NULL;
        GetDisplayNameFromPath(RemoteDir, DisplayName);
        // get password from main thread
        pConnectSettings oldserverid = (pConnectSettings)GetServerIdFromName(DisplayName.c_str(), mainthreadid);
        if (oldserverid && oldserverid->password[0]) {
            oldpass = oldserverid->password;
        }
        SERVERID serverid = SftpConnectToServer(DisplayName.c_str(), inifilename, oldpass);
        if (serverid)
            SetServerIdForName(DisplayName.c_str(), serverid);
    }
    return true;
}

Icon Plugin::ExtractCustomIcon(LPCWSTR RemoteName, IconFlags ExtractFlags, HICON * TheIcon)
{
    *TheIcon = nullptr;
    if (wcslen(RemoteName) <= 1)
        return Icon::UserDefault;

    if (is_full_name(RemoteName))   // not server name!
        return Icon::UserDefault;

    if (_wcsicmp(RemoteName + 1, get_f7newconnectionW().c_str()) == 0)
        return Icon::UserDefault;

    bst::wsfp remotedir;
    SERVERID serverid = GetServerIdFromPath(RemoteName, remotedir);
    bool sm = has_flag(ExtractFlags, IconFlag::Small);
    // show different icon when connected!
    LPCSTR lpIconName;
    if (serverid == nullptr)
        lpIconName = MAKEINTRESOURCEA(sm ? IDI_ICON1SMALL : IDI_ICON1);
    else
        lpIconName = MAKEINTRESOURCEA(sm ? IDI_ICON2SMALL : IDI_ICON2);
    *TheIcon = LoadIconA(hinst, lpIconName);
    return Icon::Extracted;
}

HashFlags Plugin::ServerSupportsChecksums(LPCWSTR RemoteName)
{
    bst::wsfp remotedir;
    pConnectSettings serverid = GetServerIdFromPath(RemoteName, remotedir);
    if (serverid == nullptr)
        return HashFlag::_Empty;
    ResetLastPercent(serverid);
    int rc = SftpServerSupportsChecksumsW(serverid, remotedir.c_str());
    return (HashFlags)rc;
}

HANDLE Plugin::StartFileChecksum(HashFlags ChecksumType, LPCWSTR RemoteName)
{
    bst::wsfp remotedir;
    pConnectSettings serverid = GetServerIdFromPath(RemoteName, remotedir);
    if (serverid == nullptr)
        return nullptr;
    ResetLastPercent(serverid);
    return SftpStartFileChecksumW((int)ChecksumType, serverid, remotedir.c_str());
}

int Plugin::GetFileChecksumResult(bool WantResult, HANDLE ChecksumHandle, LPCWSTR RemoteName, LPSTR checksum, int maxlen)
{
    bst::wsfp remotedir;
    pConnectSettings serverid = GetServerIdFromPath(RemoteName, remotedir);
    if (serverid == nullptr)
        return 0;  /* length = 0 */
    ResetLastPercent(serverid);
    return SftpGetFileChecksumResultW(WantResult, ChecksumHandle, serverid, checksum, maxlen);
}


} /* namespace */

