#pragma once

#include <windows.h>
#include "bst\string.hpp"
#include "bst\log.hpp"
#include "version.h"


namespace wfx {

namespace ini {
    static const char filename[] = WFX_INTERNAL_NAME ".ini";
    static const WCHAR settings[] = L"base_settings";
};

namespace lng {
    static const WCHAR ext[]      = L".lng";
    static const WCHAR subdir[]   = L"lang";
    static const WCHAR section[]  = L"lang";
};

enum class Proxy : int
{
    notused = 0,
    default = 1,
    http    = 2,
    socks4  = 3,
    socks5  = 4,
};

enum class PassSaveMode : int
{
    empty   = 0,   /* without password */
    crypt   = 1,   /* use TotalCmd as password agent */
    plain   = 2,   /* plaintext */
};

class CfgProxy
{
public:
    Proxy     m_type = Proxy::notused;
    bst::str  m_server;
    bst::str  m_user;
    bst::str  m_password;
};

class Cfg
{
public:
    enum class Switch : int {
        Auto = -1,
        No   = 0,
        Yes  = 1,
    };

    enum class Protocol : int {
        Auto = 0,
        IPv4 = 1,
        IPv6 = 2,
    };

    bst::str   m_name;     // DisplayName
    bst::str   m_server;
    bst::str   m_user;
    bst::str   m_password;
    
    bst::str   m_connect_send_cmd;
    bst::str   m_fingerprint;    // savedfingerprint
    bst::str   m_pubkey_file;
    bst::str   m_privkey_file;
    bool       m_use_agent = false;
    Protocol   m_protocol = Protocol::Auto;    // 0 = auto,  1 = IPv4,  2 = IPv6
    int        m_custom_port = 22;
    int        m_file_mod = 0644;
    int        m_dir_mod  = 0755;
    bool       m_scp_only = false;
    bool       m_scp_for_data = false;
    bool       m_compressed = false;
    bool       m_detailed_log = false;
    Switch     m_utf8_names = Switch::Auto;        // 0=no, 1=yes, -1=auto-detect
    int        m_codepage = 0;                     // only used when utf8names=0
    Switch     m_unix_line_breaks = Switch::Auto;  // 0=no, 1=yes, -1=auto-detect
    Switch     m_scp_server_64bit = Switch::Auto;  // 0=no, 1=yes, -1, auto-detect -> Support file upload/download > 2GB only if SCP on server side is 64bit!
    int        m_proxy_num = 0;                    // 0=no proxy, >0 use entry  [proxy], [proxy2] etc.
    CfgProxy   m_proxy;
    int        m_keepAliveInterval = 0;            // 0 (disabled) by default

    //bool       m_dialog_for_connection = false;
    //bst::wstr  m_last_active_path;
    //int        m_sendcommandmode = 0;
    //bool       m_neednewchannel = false;   // kill the sftp channel in case of an error
    //SYSTICKS findstarttime; // time findfirstfile started, MUST be int
    //bool  scpserver64bittemporary;  // true=user allowed transfers>2GB
    //SYSTICKS lastpercenttime;
    //int lastpercent;
    //sftp::PassSaveMode passSaveMode;
    //bool InteractivePasswordSent;
    //int trycustomlistcommand;  // set to 2 initially, reduce to 1 or 0 if failing
    //HWND hWndKeepAlive;
  
};

class BaseConfig
{
public:
    int m_debug_level = BST_LL_DEBUG;

    int get_debug_level() { return m_debug_level; }
    bool set_debug_level(int dbg_level);
};

class Dialog;   /* forward declaration */

class IniCfg
{
public:
    friend class Dialog;
    friend class Cfg;

    wfx::Cfg get_cfg(bst::c_str & name);
    bool init(HMODULE mod_addr);
    bool show_cfg_dialog(HINSTANCE dllInstance, HWND parentWnd, bst::c_str & name);
    //void set_compression_level(int cmp_level);
    bool update_lang();
    void set_lang(bst::c_wstr & lang);

protected:
    int get_bool(bst::c_str & name, bst::c_wstr & key, bool * value);
    int get_int(bst::c_str & name, bst::c_wstr & key, int defval = -1);
    int get_int(bst::c_str & name, bst::c_wstr & key, int * value);
    int get_str(bst::c_str & name, bst::c_wstr & key, bst::str & value);
    int get_str(bst::c_str & name, bst::c_wstr & key, bst::str & value, bst::c_wstr & defval);

protected:
    bool load_from_ini(bst::c_str & name, wfx::Cfg & cfg);
    bool load_proxy_cfg(bst::c_str & name, int proxynr, wfx::Cfg & cfg);
    bool check_lang_file_by_name(bst::c_wstr & lang);
    //int save_to_ini();
    //int save_to_ini(wfx::Cfg & cfg);

    //wfx::Cfg * get_cfg_by_name(bst::c_str & name);

    BaseConfig     m_basecfg;
    //bst::list<wfx::Cfg> m_cfg;
    wfx::Cfg       m_cfg;
    bst::srw_mutex m_mutex;        // SRW lock for m_cfg;

    UINT64         m_last_load_time;
    bst::wstr      m_exe_path;     // COMMANDER_PATH
    bst::wstr      m_wfx_path;
    bst::wstr      m_ini_file;
    bst::wstr      m_lng_path;
    bst::wstr      m_lang;         // "en", "en-EN", "en-AU", "ru", "ru-RU"
    bst::wstr      m_lang_file;
};

} /* namespace */

