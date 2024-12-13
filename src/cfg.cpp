#include "utils.h"
#include "cfg.h"
#include "bst/core.hpp"


namespace wfx {

bool BaseConfig::set_debug_level(int dbg_level)
{
    m_debug_level = dbg_level;
    if (dbg_level < BST_LL_ERROR)
        m_debug_level = BST_LL_ERROR;
    if (dbg_level > BST_LL_TRACE)
        m_debug_level = BST_LL_TRACE;
    return true;
}

// =====================================================================================

static LPCSTR cfg_error_text = "Config load error";

int IniCfg::get_int(bst::c_str & name, bst::c_wstr & key, int defval)
{
    bst::wsfn secname;
    secname.assign_fmt(L"%S", name.c_str());
    return (int)GetPrivateProfileIntW(secname.c_str(), key.c_str(), defval, m_ini_file.c_str());
}

int IniCfg::get_int(bst::c_str & name, bst::c_wstr & key, int * value)
{
    bst::wsfn secname;
    secname.assign_fmt(L"%S", name.c_str());
    int x = (int)GetPrivateProfileIntW(secname.c_str(), key.c_str(), -1888000, m_ini_file.c_str());
    if (value && x != -1888000)
        *value = x;
    return x;
}

int IniCfg::get_bool(bst::c_str & name, bst::c_wstr & key, bool * value)
{
    bst::wsfn secname;
    secname.assign_fmt(L"%S", name.c_str());
    int x = (int)GetPrivateProfileIntW(secname.c_str(), key.c_str(), -1888000, m_ini_file.c_str());
    if (value && x != -1888000)
        *value = (x == 0) ? false : true;
    return x;
}

int IniCfg::get_str(bst::c_str & name, bst::c_wstr & key, bst::str & value)
{
    LPCWSTR defval = L"##{7E14B08B-0DF2-4E2D-9258-D651B61389D0}##";
    bst::wsfn secname;
    secname.assign_fmt(L"%S", name.c_str());
    bst::wsfn val;
    DWORD len = GetPrivateProfileStringW(secname.c_str(), key.c_str(), defval, val.data(), val.capacity(), m_ini_file.c_str());
    if (len == wcslen(defval) && wcscmp(val.c_str(), defval) == 0)
        return -1;   // not found
    value.clear();
    val.fix_length();
    if (val.length())
        value.append_fmt("%S", val.c_str());
    return (int)value.length();
}

int IniCfg::get_str(bst::c_str & name, bst::c_wstr & key, bst::str & value, bst::c_wstr & defval)
{
    value.clear();
    bst::wsfn secname;
    secname.assign_fmt(L"%S", name.c_str());
    bst::wsfn def;
    def.assign_fmt(L"%S", defval);
    bst::wsfn val;
    DWORD len = GetPrivateProfileStringW(secname.c_str(), key.c_str(), defval.c_str(), val.data(), val.capacity(), m_ini_file.c_str());
    val.fix_length();
    if (val.length())
        value.append_fmt("%S", val.c_str());
    return (int)value.length();
}

bool IniCfg::init(HMODULE mod_addr)
{
    m_wfx_path.clear();
    m_wfx_path.reserve(MAX_PATH);
    DWORD nlen = GetModuleFileNameW(mod_addr, m_wfx_path.data(), MAX_PATH);
    BST_THROW_IF(nlen < 4 || nlen >= MAX_PATH, C, 2, cfg_error_text);
    BST_THROW_IF(GetLastError() != ERROR_SUCCESS, C, 3, cfg_error_text);  
    m_wfx_path.fix_length();
    //WLOGd(L"wfx path = '%s'", m_wfx_path.c_str());
    size_t pos = m_wfx_path.rfind(L'\\');
    m_wfx_path.resize(pos + 1);

    m_exe_path.clear();
    m_exe_path.reserve(MAX_PATH);
    nlen = GetModuleFileNameW(NULL, m_exe_path.data(), MAX_PATH);
    BST_THROW_IF(nlen < 4 || nlen >= MAX_PATH, C, 4, cfg_error_text);
    BST_THROW_IF(GetLastError() != ERROR_SUCCESS, C, 5, cfg_error_text);  
    m_exe_path.fix_length();
    //WLOGd(L"exe path = '%s'", m_exe_path.c_str());
    pos = m_exe_path.rfind(L'\\');
    m_exe_path.resize(pos + 1);

    m_ini_file.assign(m_wfx_path);
    m_ini_file.append_fmt(L"%S", ini::filename);
    DWORD dw = GetFileAttributesW(m_ini_file.c_str());
    if (dw == INVALID_FILE_ATTRIBUTES) {
        bst::wstr ifile = m_exe_path;
        ifile.append_fmt(L"%S", ini::filename);
        dw = GetFileAttributesW(ifile.c_str());
        if (dw != INVALID_FILE_ATTRIBUTES) {
            m_ini_file = ifile;
        }
    }
    WLOGd(L"INI = \"%s\" ", m_ini_file.c_str());
    return update_lang();
}

wfx::Cfg IniCfg::get_cfg(bst::c_str & name)
{
    bst::scoped_read_lock lock(m_mutex);
    wfx::Cfg cfg;
    bool x = load_from_ini(name, cfg);
    BST_THROW_IF(!x, U, 1901, "Config not found");
    return cfg;
}

bool IniCfg::load_from_ini(bst::c_str & name, wfx::Cfg & cfg)
{
    int val;
    bst::str str;
    cfg = wfx::Cfg();  // set defaults

    BST_THROW_IF(m_ini_file.empty(), C, 11, cfg_error_text);
    DWORD dw = GetFileAttributesW(m_ini_file.c_str());
    if (dw == INVALID_FILE_ATTRIBUTES)
        return false;

#ifdef WFX_DEBUG
    val = (int)GetPrivateProfileIntW(ini::settings, L"DebugLevel", -1, m_ini_file.c_str());
    if (val >= 0) {
        m_basecfg.set_debug_level(val);
        LOGi("%s: debug level = %d ", __func__, val);
        bst::log::SetLogLevel(val);
    }
#endif
    get_str(name, L"server", cfg.m_server);
    get_int(name, L"protocol", (int*)&cfg.m_protocol);
    get_str(name, L"user", cfg.m_user);
    get_str(name, L"fingerprint", cfg.m_fingerprint);
    get_str(name, L"pubkeyfile", cfg.m_pubkey_file);
    get_str(name, L"privkeyfile", cfg.m_privkey_file);
    get_bool(name, L"useagent", &cfg.m_use_agent);
    val = get_str(name, L"filemod", str);
    if (val > 0)
        cfg.m_file_mod = strtol(str.c_str(), NULL, 8);
    val = get_str(name, L"dirmod", str);
    if (val > 0)
        cfg.m_dir_mod = strtol(str.c_str(), NULL, 8);
    get_bool(name, L"compression", &cfg.m_compressed);
    get_bool(name, L"scpfordata", &cfg.m_scp_for_data);
    get_bool(name, L"scponly", &cfg.m_scp_only);
    if (cfg.m_scp_only)
        cfg.m_scp_for_data = true;
    get_int(name, L"keepaliveseconds", &cfg.m_keepAliveInterval);
    get_bool(name, L"compression", &cfg.m_compressed);
    get_int(name, L"utf8", (int*)&cfg.m_utf8_names);
    get_int(name, L"codepage", &cfg.m_codepage);
    get_int(name, L"unixlinebreaks", (int*)&cfg.m_unix_line_breaks);
    get_int(name, L"largefilesupport", (int*)&cfg.m_scp_server_64bit);
    bst::str pass;
    get_str(name, L"password", pass, L"");
    if (pass.length()) {
        if (cfg.m_use_agent && pass.equal("!")) {
            cfg.m_password = "\001";
        }
        else {
            bool x = cipher::DecryptString(pass, cfg.m_password);
        }
    }
    get_str(name, L"sendcommand", cfg.m_connect_send_cmd);
    int pnum = get_int(name, L"proxynr");
    if (pnum > 0) {

    }
    return cfg.m_server.length() ? true : false;
}

bool IniCfg::load_proxy_cfg(bst::c_str & name, int proxynr, wfx::Cfg & cfg)
{
    cfg.m_proxy = CfgProxy();  // set defaults
    CfgProxy & pcfg = cfg.m_proxy;
    if (proxynr <= 0)
        return false;
    bst::sfn proxyentry;
    if (proxynr > 1)
        proxyentry.assign_fmt("proxy%d", proxynr);
    else
        proxyentry.assign("proxy");
    int type = get_int(proxyentry, L"proxytype", -1);
    if (type >= 0)
        pcfg.m_type = (Proxy)type;
    get_str(proxyentry, L"proxyserver", pcfg.m_server);
    get_str(proxyentry, L"proxyuser", pcfg.m_user);
    bst::str pass;
    get_str(proxyentry, L"proxypassword", pass, L"");
    if (pass.length()) {
        bool x = cipher::DecryptString(pass, pcfg.m_password);
    }
    return (type != -1 || proxynr == 1);   // nr 1 is always valid
}
/*
int IniCfg::save_to_ini(wfx::Cfg & cfg)
{
    int hr = 0;
    bst::filename str;

    FIN_IF(m_ini_file.empty(), -21);
    DWORD dw = GetFileAttributesW(m_ini_file.c_str());
    FIN_IF(dw == INVALID_FILE_ATTRIBUTES, -22);

#ifdef WFX_DEBUG
    str.assign_fmt(L"%d", cfg.get_debug_level());
    WritePrivateProfileStringW(ini::settings, L"DebugLevel", str.c_str(), m_ini_file.c_str());
#endif
    str.assign_fmt(L"%d", cfg.get_compression_level());
    WritePrivateProfileStringW(ini::settings, L"CompressionLevel", str.c_str(), m_ini_file.c_str());
  
    str.assign_fmt(L"%d", cfg.get_cache_lifetime());
    WritePrivateProfileStringW(ini::settings, L"CacheLifetime", str.c_str(), m_ini_file.c_str());

    str.assign_fmt(L"%d", (int)cfg.get_attr_time());
    WritePrivateProfileStringW(ini::settings, L"FileTimeFlags", str.c_str(), m_ini_file.c_str());

    str.assign_fmt(L"%d", (int)cfg.get_attr_file());
    WritePrivateProfileStringW(ini::settings, L"FileAttrFlags", str.c_str(), m_ini_file.c_str());

    LOGd("%s: INI saved! ", __func__);
    hr = 0;

fin:  
    return hr;
}

int IniCfg::save_to_ini()
{
  wfx::Cfg cfg;
  {
    bst::scoped_read_lock lock(m_mutex);
    cfg = m_cfg;
  }
  return save_to_ini(cfg);
}
*/
bool IniCfg::check_lang_file_by_name(bst::c_wstr & lang)
{
    try {
        m_lang.assign(lang);
        BST_THROW_IF(m_lang.length() < 2, U, 1, "");
        m_lang_file.clear();
        m_lang_file.append(m_lng_path).append(m_lang.c_str()).append(lng::ext);
        DWORD dw = GetFileAttributesW(m_lang_file.c_str());
        if (dw != INVALID_FILE_ATTRIBUTES)
            return true;    
        size_t pos = m_lang.find(L'-');
        BST_THROW_IF(pos == bst::npos, U, 3, "");
        m_lang.resize(pos);
        BST_THROW_IF(m_lang.length() < 2, U, 4, "");
        m_lang_file.clear();
        m_lang_file.append(m_lng_path).append(m_lang.c_str()).append(lng::ext);
        dw = GetFileAttributesW(m_lang_file.c_str());
        if (dw != INVALID_FILE_ATTRIBUTES)
            return true;
    }
    catch (const bst::exception_base<bst::err::U> &) {
        // nothing
    }
    m_lang.clear();
    m_lang_file.clear();
    return false;
}

bool IniCfg::update_lang()
{
    WCHAR lang[64] = { 0 };  
    m_lang.clear();
    m_lang_file.clear();
    try {
        if (m_lng_path.empty())
            m_lng_path.append(m_wfx_path).append(lng::subdir).append(L"\\");

        DWORD plen = GetPrivateProfileStringW(ini::settings, L"Lang", NULL, lang, 62, m_ini_file.c_str());
        if (plen >= 2 && plen < 60) {
            WLOGd(L"%S: read Lang = '%s' ", __func__, lang);
            bool x = check_lang_file_by_name(lang);
            WLOGd_IF(x, L"%S: set Lang = '%s' ", __func__, m_lang.c_str());
            if (x)
                return true;
        }
        int len;
        LCID lcid = GetUserDefaultLCID();
        LANGID langid = LOWORD(lcid);
        len = GetLocaleInfoW(MAKELCID(langid, SORT_DEFAULT), LOCALE_SISO639LANGNAME, lang, 20);
        BST_THROW_IF(len < 2, U, 5, "");
        wcscat(lang, L"-");
        LPWSTR country = lang + wcslen(lang);
        len = GetLocaleInfoW(MAKELCID(langid, SORT_DEFAULT), LOCALE_SISO3166CTRYNAME, country, 20);
        BST_THROW_IF(len < 2, U, 6, "");
        bool x = check_lang_file_by_name(lang);
        WLOGd_IF(x, L"%S: SET Lang = '%s' ", __func__, m_lang.c_str());
        if (x)
            return true;
    }
    catch (const bst::exception_base<bst::err::U> &) {
        // 
    }
    m_lang.assign(L"en");
    m_lang_file.clear();
    m_lang_file.append(m_lng_path).append(m_lang).append(lng::ext);
    WLOGd(L"%S: LangFile = \"%s\" ", __func__, m_lang_file.c_str());
    return false;
}
/*
void IniCfg::set_compression_level(int cmp_level)
{
  {
    bst::scoped_write_lock lock(m_mutex);
    m_cfg.set_compression_level(cmp_level);
  }
  bst::prealloc_string<WCHAR, 16> str(bst::fmtstr(L"%d"), m_cfg.get_compression_level());
  WritePrivateProfileStringW(ini::settings, L"CompressionLevel", str.c_str(), m_ini_file.c_str());
}
*/
void IniCfg::set_lang(bst::c_wstr & lang)
{
    WritePrivateProfileStringW(ini::settings, L"Lang", lang.c_str(), m_ini_file.c_str());
    m_lang.assign(lang);
}

bool IniCfg::show_cfg_dialog(HINSTANCE dllInstance, HWND parentWnd, bst::c_str & name)
{
    bool x;
    update_lang();
    wfx::Cfg cfg;
    x = load_from_ini(name, cfg);
    //wfx::Dialog dlg(*this, dllInstance, parentWnd);
    int ret = 0; // dlg.show();
    if (ret == IDOK) {
        bst::scoped_write_lock lock(m_mutex);
        //m_cfg.assign(dlg.get_cfg());
        //save_to_ini(m_cfg);
    }
    return true;
}

} /* namespace */

