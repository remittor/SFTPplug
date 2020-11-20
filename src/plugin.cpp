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

int Plugin::init(tCryptProc pCryptProc, int CryptoNr, int Flags) noexcept
{
    ::CryptProc = pCryptProc;
    ::CryptCheckPass = (Flags & FS_CRYPTOPT_MASTERPASS_SET) != 0;
    ::CryptoNumber = CryptoNr;

    m_cb.CryptProc = pCryptProc;
    m_CryptCheckPass = (Flags & FS_CRYPTOPT_MASTERPASS_SET) != 0;
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
    //BST_THROW(C, 100, "Resource read error111");   // test

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

bool Plugin::RequestMsgOK(bst::c_str & title, bst::c_str & text)
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
        RequestMsgOK("SFTP Error", buf.c_str());
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

bool Plugin::disconnect(LPCSTR DisconnectRoot)
{
    LOGt("%s: '%s' ", __func__, DisconnectRoot);
    bst::sfp DisplayName;
    GetDisplayNameFromPath(DisconnectRoot, DisplayName.data(), DisplayName.max_len);
    SERVERID serverid = GetServerIdFromName(DisplayName.c_str(), GetCurrentThreadId());
    if (serverid) {
        LogMessageEx(false, MsgType::Disconnect, 0, "DISCONNECT \\%s", DisplayName.c_str());
        SftpCloseConnection(serverid);
        SetServerIdForName(DisplayName.c_str(), NULL); // this frees it too!
    }
    return true;
}



} /* namespace */

