#include "utils.h"
#include "dialogs.h"
#include "plugin.h"
#include "res\resource.h"
#include <CommCtrl.h>


namespace wfx {

Dialog::Dialog(wfx::Plugin & plg, wfx::IniCfg & ini, bst::c_str & name)
  : m_plg(plg)
  , m_ini(ini)
{
    m_name = name;
    m_dll = plg.m_module;
    m_parent_wnd = GetActiveWindow();
    m_wnd = NULL;
    m_idc = IDD_WEBDAV;
    m_hFixedFont = NULL;
    m_result = 0;
}

Dialog::~Dialog()
{
    if (m_hFixedFont)
        DeleteObject(m_hFixedFont);
}

bool Dialog::set_button_check(int idc, int checked)
{
    return !!CheckDlgButton(m_wnd, idc, checked ? BST_CHECKED : BST_UNCHECKED);
}
/*
void Dialog::set_file_time_checkbox(cfg::AttrTime flags)
{
    set_button_check(IDC_LBL_SAVE_CREATE_TIME, flags & cfg::save_ctime);
    set_button_check(IDC_LBL_SAVE_CREATE_TIME, flags & cfg::save_ctime);
    set_button_check(IDC_LBL_SAVE_ACCESS_TIME, flags & cfg::save_atime);
}

void Dialog::set_file_attr_checkbox(cfg::AttrFile flags)
{
    set_button_check(IDC_LBL_SAVE_READONLY, flags & cfg::save_readonly);
    set_button_check(IDC_LBL_SAVE_HIDDEN,   flags & cfg::save_hidden);
    set_button_check(IDC_LBL_SAVE_SYSTEM,   flags & cfg::save_system);
    set_button_check(IDC_LBL_SAVE_ARCHIVE,  flags & cfg::save_archive);
}
*/
static INT_PTR CALLBACK WfxConfigDialog(HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    Dialog * dlg;
    if (msg == WM_INITDIALOG) {
        dlg = (Dialog *)lParam;
    } else {
        dlg = (Dialog *)GetWindowLongPtrW(hwndDlg, GWLP_USERDATA);
    }
    switch (msg) {
    case WM_INITDIALOG:
        return dlg->wm_init(hwndDlg, wParam);

    //case WM_CTLCOLORSTATIC:
    //    return dlg->wm_control_color_static((HWND)lParam, (HDC)wParam);

    case WM_SHOWWINDOW:
        if (dlg->m_plg.m_focus_set)
            SetFocus(GetDlgItem(dlg->m_wnd, dlg->m_plg.m_focus_set));
        break;

    case WM_COMMAND:
        return dlg->wm_command(LOWORD(wParam), HIWORD(wParam));

    case WM_NOTIFY:
        break;

    case WM_DESTROY:
        return dlg->wm_destroy();
    }
    return FALSE;
}

int Dialog::show()
{
    m_cfg = m_ini.get_cfg(m_name);
    m_result = 0;
    DialogBoxParamW(m_dll, MAKEINTRESOURCEW(m_idc), m_parent_wnd, WfxConfigDialog, (LPARAM)this);
    return m_result;
}

bool Dialog::wm_destroy()
{
    if (m_hFixedFont)
        DeleteObject(m_hFixedFont);
    m_hFixedFont = NULL;
    return true;
}

LPCWSTR Dialog::get_control_name(int idc, bst::wsfn & name, LPCWSTR default_name)
{
    bst::wsfn key;
    key.assign_fmt(L"%d", idc);
    DWORD plen = GetPrivateProfileStringW(lng::section, key.c_str(), NULL, name.data(), name.capacity(), m_ini.m_lang_file.c_str());
    name.fix_length();
    return (plen > 0 && plen < name.capacity()) ? name.c_str() : default_name;
}

static BOOL CALLBACK TranslateDialogEnumProc(HWND hwnd, LPARAM lParam)
{
    Dialog * dlg = (Dialog *)lParam;
    bst::wsfn buf;
    LPCWSTR name = dlg->get_control_name(dlg->m_idc + GetDlgCtrlID(hwnd), buf);
    if (name)
        SetWindowTextW(hwnd, name);
    return TRUE;
}

bool Dialog::translate()
{
    bst::wsfn buf;
    LPCWSTR name = get_control_name(m_idc, buf);
    if (name)
        SetWindowTextW(m_wnd, name);
    EnumChildWindows(m_wnd, TranslateDialogEnumProc, (LPARAM)this);
    return true;
}

int Dialog::combobox_add(int idc, LPCWSTR txt, int data)
{
    int index = (int)SendDlgItemMessageW(m_wnd, idc, CB_ADDSTRING, 0, (LPARAM)txt);
    if (index >= 0)
        SendDlgItemMessageW(m_wnd, idc, CB_SETITEMDATA, (WPARAM)index, (LPARAM)data);
    return index;
}

int Dialog::combobox_add(int idc, int data)
{
    bst::wsfn wstr;
    wstr.assign_fmt(L" %d", data);
    return combobox_add(idc, wstr.c_str(), data);
}

int Dialog::get_combobox_seleted_data(int idc)
{
    int index = (int)SendDlgItemMessageW(m_wnd, idc, CB_GETCURSEL, (WPARAM)0, (LPARAM)0);
    if (index < 0)
        return -1;
    return (int)SendDlgItemMessageW(m_wnd, idc, CB_GETITEMDATA, (WPARAM)index, (LPARAM)0);
}

int Dialog::get_compression_level()
{
    return 0; // get_combobox_seleted_data(IDC_COMP_LEVEL);
}

bool Dialog::show_control(int idc)
{
    HWND wnd = GetDlgItem(m_wnd, idc);
    if (!wnd)
        return false;
    ShowWindow(wnd, SW_SHOW);
    return true;
}

bool Dialog::enable_controls()
{
    //int index = SendDlgItemMessage(m_wnd, IDC_COMP_LEVEL, CB_GETCURSEL, (WPARAM)0, (LPARAM)0);
    //EnableWindow(GetDlgItem(m_wnd, IDC_COMP_METHOD), bEnable);
    //EnableWindow(GetDlgItem(m_wnd, IDC_DICT_SIZE), bEnable);
    return true;
}

static int codepagelist[] = {
    -1, -2, 0, 1, 2, 1250, 1251, 1252, 1253, 1254, 1255, 1256, 1257, 1258,
    936, 950, 932, 949, 874, 437, 850, 20866, -3, -4
};

void Dialog::EnableControlsPageant(bool enable)
{
    EnableWindow(GetDlgItem(m_wnd, IDC_CERTFRAME), enable);
    EnableWindow(GetDlgItem(m_wnd, IDC_STATICPUB), enable);
    EnableWindow(GetDlgItem(m_wnd, IDC_STATICPEM), enable);
    EnableWindow(GetDlgItem(m_wnd, IDC_PUBKEY), enable);
    EnableWindow(GetDlgItem(m_wnd, IDC_PRIVKEY), enable);
    EnableWindow(GetDlgItem(m_wnd, IDC_LOADPUBKEY), enable);
    EnableWindow(GetDlgItem(m_wnd, IDC_LOADPRIVKEY), enable);
}

static bool GetDialogPosition(HWND hWnd, POINT * pos)
{
    RECT rt1, rt2;
    if (GetWindowRect(hWnd, &rt1) && GetWindowRect(GetParent(hWnd), &rt2)) {
        int w = rt2.right  - rt2.left;
        int h = rt2.bottom - rt2.top;
        int DlgWidth   = rt1.right  - rt1.left;
        int DlgHeight  = rt1.bottom - rt1.top;
        pos->x = rt2.left + (w - DlgWidth)/2;
        pos->y = rt2.top  + (h - DlgHeight)/2;
        return true;
    }
    return false;
}

bool Dialog::SetDialogPosToCenter(DWORD dwFlags)
{
    POINT pos;
    if (!GetDialogPosition(m_wnd, &pos))
        return false;
    BOOL x = SetWindowPos(m_wnd, 0, pos.x, pos.y, 0, 0, dwFlags);
    return !!x;
}

bool Dialog::update_combos()
{
    //int comp_level = get_compression_level();
    return true;
}

void Dialog::set_combobox_height(int idc, int nItems)
{
    HWND wnd = GetDlgItem(m_wnd, idc);
    RECT rect;      
    int h = (int)SendMessageW(wnd, CB_GETITEMHEIGHT, 0, 0);
    GetWindowRect(wnd, &rect);
    SetWindowPos(wnd, 0, 0, 0, rect.right - rect.left, h * (nItems+2), SWP_NOMOVE | SWP_NOZORDER);
}

bool Dialog::wm_init(HWND hwndDlg, WPARAM wParam)
{
    bst::filename_a str;
    bst::filename   wstr;
  
    m_wnd = hwndDlg;
    SetWindowLongPtrW(m_wnd, GWLP_USERDATA, (LONG_PTR)this);
    //translate();

    SendDlgItemMessageW(m_wnd, IDC_DEFAULTCOMBO, CB_SETCURSEL, 0, 0);
    m_server_field_changed_by_user = false;

    SendDlgItemMessageW(m_wnd, IDC_UTF8, CB_ADDSTRING, 0, (LPARAM)m_plg.get_resW(IDS_AUTO).c_str());
    for (int i = IDS_UTF8; i <= IDS_OTHER; i++) {
        SendDlgItemMessageW(m_wnd, IDC_UTF8, CB_ADDSTRING, 0, (LPARAM)m_plg.get_resW(i).c_str());
    }

    SendDlgItemMessageW(m_wnd, IDC_SYSTEM, CB_ADDSTRING, 0, (LPARAM)m_plg.get_resW(IDS_AUTO).c_str());
    SendDlgItemMessageW(m_wnd, IDC_SYSTEM, CB_ADDSTRING, 0, (LPARAM)L"Windows (CR/LF)");
    SendDlgItemMessageW(m_wnd, IDC_SYSTEM, CB_ADDSTRING, 0, (LPARAM)L"Unix (LF)"); 

    CheckRadioButton(m_wnd, IDC_PROTOAUTO, IDC_PROTOV6, IDC_PROTOAUTO);
    SetDlgItemTextW(m_wnd, IDC_FILEMOD, L"644");
    SetDlgItemTextW(m_wnd, IDC_DIRMOD, L"755");
    SendDlgItemMessageW(m_wnd, IDC_UTF8, CB_SETCURSEL, 0, 0);
    SendDlgItemMessageW(m_wnd, IDC_SYSTEM, CB_SETCURSEL, 0, 0);

    if (!m_plg.is_quick_connect(m_name)) {
        SetDlgItemTextA(m_wnd, IDC_CONNECTTO, m_cfg.m_server.c_str());
        if (!m_cfg.m_server.empty())
            m_server_field_changed_by_user = true;

        int btn = IDC_PROTOAUTO;
        switch (m_cfg.m_protocol) {
        case Cfg::Protocol::IPv4: btn = IDC_PROTOV4; break;
        case Cfg::Protocol::IPv6: btn = IDC_PROTOV6; break;
        }
        CheckRadioButton(m_wnd, IDC_PROTOAUTO, IDC_PROTOV6, btn);

        SetDlgItemTextA(m_wnd, IDC_USERNAME, m_cfg.m_user.c_str());

        CheckDlgButton(m_wnd, IDC_USEAGENT, m_cfg.m_use_agent ? BST_CHECKED : BST_UNCHECKED);
        EnableControlsPageant(m_cfg.m_use_agent ? false : true);
        CheckDlgButton(m_wnd, IDC_DETAILED_LOG, m_cfg.m_detailed_log ? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(m_wnd, IDC_COMPRESS, m_cfg.m_compressed ? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(m_wnd, IDC_SCP_DATA, m_cfg.m_scp_for_data? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(m_wnd, IDC_SCP_ALL, m_cfg.m_scp_only ? BST_CHECKED : BST_UNCHECKED);
        if (m_cfg.m_keepAliveInterval > 0) {
            CheckDlgButton(m_wnd, IDC_KEEP_ALIVE, BST_CHECKED);
            str.assign_fmt("%d", m_cfg.m_keepAliveInterval);
            SetDlgItemTextA(m_wnd, IDC_KEEP_ALIVE_SECONDS, str.c_str());
        }
        else {
            ::EnableWindow(GetDlgItem(m_wnd, IDC_KEEP_ALIVE_SECONDS), FALSE);
        }
        int cbline = 0;
        switch (m_cfg.m_utf8_names) {
        case Cfg::Switch::Auto: cbline = 0; break;  // auto-detect
        case Cfg::Switch::Yes:  cbline = 1; break;
        default:
            cbline = 0;
            int cp = m_cfg.m_codepage;
            for (int i = 0; i < _countof(codepagelist); i++) {
                if (cp == codepagelist[i]) {
                    cbline = i;
                    break;
                }
            }
            if (cp > 0 && cbline == 0) {
                str.assign_fmt("%d", cp);
                SendDlgItemMessageA(m_wnd, IDC_UTF8, CB_ADDSTRING, 0, (LPARAM)str.c_str());
                cbline = _countof(codepagelist) - 1;
            }
        }
        SendDlgItemMessageA(m_wnd, IDC_UTF8, CB_SETCURSEL, cbline, 0);

        SendDlgItemMessageA(m_wnd, IDC_SYSTEM, CB_SETCURSEL, max(0, min(2, (int)m_cfg.m_unix_line_breaks + 1)), 0);

        if (m_cfg.m_password.equal("\001") && m_plg.m_cb.CryptProc) {
            str = m_cfg.m_password;
            if (m_plg.PasswordLoad(m_name, str, true)) {
                m_cfg.m_password = str;
                SetDlgItemTextA(m_wnd, IDC_PASSWORD, m_cfg.m_password.c_str());
                CheckDlgButton(m_wnd, IDC_CRYPTPASS, BST_CHECKED);
            } else {
                ShowWindow(GetDlgItem(m_wnd, IDC_PASSWORD), SW_HIDE);
                ShowWindow(GetDlgItem(m_wnd, IDC_CRYPTPASS), SW_HIDE);
                ShowWindow(GetDlgItem(m_wnd, IDC_EDITPASS), SW_SHOW);
            }
        } else {
            SetDlgItemTextA(m_wnd, IDC_PASSWORD, m_cfg.m_password.c_str());
            EnableWindow(GetDlgItem(m_wnd, IDC_CRYPTPASS), m_plg.m_cb.CryptProc ? true : false);
            if (m_plg.m_cb.CryptProc && m_cfg.m_password.empty() && m_plg.m_CryptCheckPass)
                CheckDlgButton(m_wnd, IDC_CRYPTPASS, BST_CHECKED);
        }

        SetDlgItemTextA(m_wnd, IDC_PUBKEY, m_cfg.m_pubkey_file.c_str());
        SetDlgItemTextA(m_wnd, IDC_PRIVKEY, m_cfg.m_privkey_file.c_str());

        str.assign_fmt("%o", m_cfg.m_file_mod);
        SetDlgItemTextA(m_wnd, IDC_FILEMOD, str.c_str());
        str.assign_fmt("%o", m_cfg.m_dir_mod);
        SetDlgItemTextA(m_wnd, IDC_DIRMOD, str.c_str());

        //fillProxyCombobox(hWnd, gConnectResults->proxynr);
    }
    m_plg.m_focus_set = IDC_CONNECTTO;
    if (!m_plg.is_quick_connect(m_name)) {
        if (m_cfg.m_server.empty())
            m_plg.m_focus_set = IDC_CONNECTTO;
        else if (m_cfg.m_user.empty())
            m_plg.m_focus_set = IDC_USERNAME;
        else
            m_plg.m_focus_set = IDC_PASSWORD;
    }
    // trying to center the About dialog
    SetDialogPosToCenter();

    m_server_field_changed_by_user = false;
    return true;
}
/*
int Dialog::wm_control_color_static(HWND wnd, HDC hdc)
{
    if ( GetDlgItem(m_wnd, IDC_TITLE) == wnd
      || GetDlgItem(m_wnd, IDC_SUBTITLE) == wnd
      || GetDlgItem(m_wnd, IDI_ICON) == wnd)
    {
        SetBkMode(hdc, TRANSPARENT);
        return GetStockObject(NULL_BRUSH) ? TRUE : FALSE;
    }
    return FALSE;
}
*/

bool Dialog::get_item_text(int idc, bst::str & text)
{
    char buf[MAX_PATH] = { 0 };
    text.clear();
    UINT len = GetDlgItemTextA(m_wnd, idc, buf, _countof(buf) - 1);
    text = buf;
    return true;
}

bool Dialog::is_button_checked(int idc)
{
    return IsDlgButtonChecked(m_wnd, idc) != BST_UNCHECKED;
}

bool Dialog::wm_command(UINT16 ctrl, UINT16 val)
{
    int hr = -1;
    wfx::Cfg defcfg;
    char modbuf[32], strbuf[MAX_PATH];
    /* TODO
    switch (ctrl) {
    case IDOK: {
        get_item_text(IDC_CONNECTTO, m_cfg.m_server);
        get_item_text(IDC_USERNAME, m_cfg.m_user);
        get_item_text(IDC_PASSWORD, m_cfg.m_password);
        m_cfg.m_protocol = wfx::Cfg::Protocol::Auto;
        if (is_button_checked(IDC_PROTOV4))
            m_cfg.m_protocol = wfx::Cfg::Protocol::IPv4;
        else if (is_button_checked(IDC_PROTOV6))
            m_cfg.m_protocol = wfx::Cfg::Protocol::IPv6;

        get_item_text(IDC_PUBKEY, m_cfg.m_pubkey_file);
        get_item_text(IDC_PRIVKEY, m_cfg.m_privkey_file);
        m_cfg.m_use_agent = is_button_checked(IDC_USEAGENT);
        m_cfg.m_detailed_log = is_button_checked(IDC_DETAILED_LOG);
        m_cfg.m_compressed = is_button_checked(IDC_COMPRESS);
        m_cfg.m_scp_for_data = is_button_checked(IDC_SCP_DATA);
        m_cfg.m_scp_only = is_button_checked(IDC_SCP_ALL);

        m_cfg.m_keepAliveInterval = 0;
        if (is_button_checked(IDC_KEEP_ALIVE)) {
            GetDlgItemTextA(m_wnd, IDC_KEEP_ALIVE_SECONDS, modbuf, _countof(modbuf));
            m_cfg.m_keepAliveInterval = atoi(modbuf);
        }

        int cp = 0;
        int cbline = (char)SendDlgItemMessageW(m_wnd, IDC_UTF8, CB_GETCURSEL, 0, 0);
        switch (cbline) {
        case 0: gConnectResults->utf8names = -1; break;  // auto-detect
        case 1: gConnectResults->utf8names = 1; break;   // FIXME: magic number!
        default:
            gConnectResults->utf8names = 0;
            if (cbline >= 0 && cbline < countof(codepagelist)) {
                cp = codepagelist[cbline];
                if (cp == -3) {
                    if (RequestProc(PluginNumber, RT_Other, "Code page", "Code page (e.g. 28591):", strbuf, sizeof(strbuf)-1)) {
                        cp = atoi(strbuf);
                    }
                } else if (cp == -4) {
                    cp = gConnectResults->codepage;  // unchanged!
                }
            }
        }
        gConnectResults->codepage = cp;

        gConnectResults->unixlinebreaks = (char)SendDlgItemMessage(hWnd, IDC_SYSTEM, CB_GETCURSEL, 0, 0) - 1;

        GetDlgItemText(hWnd, IDC_FILEMOD, modbuf, sizeof(modbuf)-1);
        if (modbuf[0] == 0)
            gConnectResults->filemod = 0644;      // FIXME: magic number!
        else
            gConnectResults->filemod = strtol(modbuf, NULL, 8);
        GetDlgItemText(hWnd, IDC_DIRMOD, modbuf, sizeof(modbuf)-1);
        if (modbuf[0] == 0)
            gConnectResults->dirmod = 0755;
        else
            gConnectResults->dirmod = strtol(modbuf, NULL, 8);

        gConnectResults->proxynr = (int)SendDlgItemMessage(hWnd, IDC_PROXYCOMBO, CB_GETCURSEL, 0, 0);
        int max = (int)SendDlgItemMessage(hWnd, IDC_PROXYCOMBO, CB_GETCOUNT, 0, 0) - 1;
        if (gConnectResults->proxynr >= max)  // "add" item!
            gConnectResults->proxynr = 0;

        if (strcmp(gDisplayName, s_quickconnect) != 0) {
            char buf[16];
            WritePrivateProfileString(gDisplayName, "server", gConnectResults->server, gIniFileName);
            WritePrivateProfileString(gDisplayName, "user", gConnectResults->user, gIniFileName);
            _itoa_s(gConnectResults->protocoltype, buf, sizeof(buf), 10);
            WritePrivateProfileString(gDisplayName, "protocol", gConnectResults->protocoltype == 0 ? NULL : buf, gIniFileName);
            WritePrivateProfileString(gDisplayName, "detailedlog", gConnectResults->detailedlog ? "1" : NULL, gIniFileName);
            WritePrivateProfileString(gDisplayName, "utf8", gConnectResults->utf8names == -1 ? NULL : gConnectResults->utf8names == 1 ? "1" : "0", gIniFileName);
            _itoa_s(gConnectResults->codepage, buf, sizeof(buf), 10);
            WritePrivateProfileString(gDisplayName, "codepage", buf, gIniFileName);
            WritePrivateProfileString(gDisplayName, "unixlinebreaks", gConnectResults->unixlinebreaks == -1 ? NULL : gConnectResults->unixlinebreaks == 1 ? "1" : "0", gIniFileName);
            WritePrivateProfileString(gDisplayName, "largefilesupport", gConnectResults->scpserver64bit == -1 ? NULL : gConnectResults->scpserver64bit == 1 ? "1" : "0", gIniFileName);
            WritePrivateProfileString(gDisplayName, "compression", gConnectResults->compressed ? "1" : NULL, gIniFileName);
            WritePrivateProfileString(gDisplayName, "scpfordata", gConnectResults->scpfordata ? "1" : NULL, gIniFileName);
            _itoa_s(gConnectResults->keepAliveIntervalSeconds, buf, sizeof(buf), 10);
            WritePrivateProfileString(gDisplayName, "keepaliveseconds", gConnectResults->keepAliveIntervalSeconds == 0 ? NULL : buf, gIniFileName);
            WritePrivateProfileString(gDisplayName, "scponly", gConnectResults->scponly ? "1" : NULL, gIniFileName);
            WritePrivateProfileString(gDisplayName, "pubkeyfile", gConnectResults->pubkeyfile[0] ? gConnectResults->pubkeyfile : NULL, gIniFileName);
            WritePrivateProfileString(gDisplayName, "privkeyfile", gConnectResults->privkeyfile[0] ? gConnectResults->privkeyfile : NULL, gIniFileName);
            WritePrivateProfileString(gDisplayName, "useagent", gConnectResults->useagent ? "1" : NULL, gIniFileName);

            _itoa_s(gConnectResults->filemod, modbuf, sizeof(modbuf), 8);
            WritePrivateProfileString(gDisplayName, "filemod", gConnectResults->filemod == 0644 ? NULL : modbuf, gIniFileName);
            _itoa_s(gConnectResults->dirmod, modbuf, sizeof(modbuf), 8);
            WritePrivateProfileString(gDisplayName, "dirmod", gConnectResults->dirmod == 0755 ? NULL : modbuf, gIniFileName);

            _itoa_s(gConnectResults->proxynr, buf, sizeof(buf), 10);
            WritePrivateProfileString(gDisplayName, TEXT("proxynr"), buf, gIniFileName);

            // SR: 09.07.2005
            if (!gConnectResults->dialogforconnection) {
                CHAR szEncryptedPassword[MAX_PATH];
                if (!IsWindowVisible(GetDlgItem(hWnd, IDC_EDITPASS))) {
                    if (gConnectResults->password[0] == 0) {
                        WritePrivateProfileString(gDisplayName, "password", NULL, gIniFileName);
                    } else if (CryptProc && IsDlgButtonChecked(hWnd, IDC_CRYPTPASS)) {
                        bool ok = CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_SAVE_PASSWORD, gDisplayName, gConnectResults->password, 0) == FS_FILE_OK;
                        WritePrivateProfileString(gDisplayName, "password", ok? "!" : NULL, gIniFileName);
                        CryptCheckPass = true;
                    } else {
                        EncryptString(gConnectResults->password, szEncryptedPassword, countof(szEncryptedPassword));
                        WritePrivateProfileString(gDisplayName, "password", szEncryptedPassword, gIniFileName);
                    }
                }
            }
        }
        gConnectResults->customport = 0;  // will be set later
        EndDialog(hWnd, IDOK);
        FIN(1);
    }
    case IDCANCEL:
    {
        // free serial number structures associated with each client certificate combo item
        int iCount = (int)SendDlgItemMessage(hWnd, IDC_CBO_CC, CB_GETCOUNT, (WPARAM)0, (LPARAM)0);

        EndDialog(hWnd, IDCANCEL);
        FIN(1);
    }
    case IDC_EDITPASS:
    {   
        int err = CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_LOAD_PASSWORD, gDisplayName, gConnectResults->password, countof(gConnectResults->password)-1);
        if (err == FS_FILE_OK || err == FS_FILE_READERROR) {
            LPCSTR txt = (err == FS_FILE_OK) ? gConnectResults->password : "";
            SetDlgItemText(hWnd, IDC_PASSWORD, txt);
            ShowWindow(GetDlgItem(hWnd, IDC_PASSWORD), SW_SHOW);
            ShowWindow(GetDlgItem(hWnd, IDC_CRYPTPASS), SW_SHOW);
            ShowWindow(GetDlgItem(hWnd, IDC_EDITPASS), SW_HIDE);
            if (gConnectResults->password[0] != 0)
                CheckDlgButton(hWnd, IDC_CRYPTPASS, BST_CHECKED);
        }
    }
    case IDC_CONNECTTO:
        if (HIWORD(wParam) == EN_CHANGE) {
            serverfieldchangedbyuser = true;
        }
        break;
    case IDC_CERTHELP:
    {
        CHAR szCaption[100];
        LoadString(hinst,  IDS_HELP_CAPTION, szCaption, countof(szCaption));
        CHAR szBuffer[1024];
        LoadString(hinst,  IDS_HELP_CERT, szBuffer, countof(szBuffer));
        MessageBox(hWnd, szBuffer, szCaption, MB_OK | MB_ICONINFORMATION);
        break;
    }
    case IDC_PASSWORDHELP:
    {
        CHAR szCaption[100];
        LoadString(hinst, IDS_HELP_CAPTION, szCaption, countof(szCaption));
        CHAR szBuffer[1024];
        LoadString(hinst, IDS_HELP_PASSWORD, szBuffer, countof(szBuffer));
        MessageBox(hWnd, szBuffer, szCaption, MB_OK | MB_ICONINFORMATION);
        break;
    }
    case IDC_UTF8HELP: 
    {
        CHAR szCaption[100];
        LoadString(hinst, IDS_HELP_CAPTION, szCaption, countof(szCaption));
        CHAR szBuffer[1024];
        LoadString(hinst, IDS_HELP_UTF8, szBuffer, countof(szBuffer));
        MessageBox(hWnd, szBuffer, szCaption, MB_OK | MB_ICONINFORMATION);
        break;
    }
    case IDC_LOADPUBKEY:
    case IDC_LOADPRIVKEY:
    {
        OPENFILENAME ofn ; // structure used by the common file dialog
        char szFileName[MAX_PATH];
        ZeroMemory(&ofn, sizeof(OPENFILENAME));
        ofn.lStructSize = sizeof(OPENFILENAME);
        ofn.hwndOwner = hWnd;
        ofn.nFilterIndex = 1;
        ofn.lpstrFile = szFileName ;
        ofn.nMaxFile = sizeof(szFileName);
        if (LOWORD(wParam) == IDC_LOADPUBKEY) {
            lstrcpy(szFileName, TEXT("*.pub"));
            ofn.lpstrFilter = TEXT("Public key files (*.pub)\0*.pub\0All Files\0*.*\0");
            ofn.lpstrTitle = TEXT("Select public key file");
        } else {
            lstrcpy(szFileName, TEXT("*.pem"));
            ofn.lpstrFilter = TEXT("Private key files (*.pem)\0*.pem\0All Files\0*.*\0");
            ofn.lpstrTitle = TEXT("Select private key file");
        }
        ofn.Flags = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY ;

        // GetOpenFileName will bring up the common file dialog in open mode
        if (GetOpenFileName(&ofn)) { // user specified a file
            SetDlgItemText(hWnd, LOWORD(wParam) == IDC_LOADPUBKEY ? IDC_PUBKEY : IDC_PRIVKEY, szFileName);
        }
        break;
    }
    case IDC_USEAGENT:
    {
        EnableControlsPageant(hWnd, !IsDlgButtonChecked(hWnd, IDC_USEAGENT));
        break;
    }
    case IDC_PROXYCOMBO:
    {
        int proxynr1 = (int)SendDlgItemMessage(hWnd, IDC_PROXYCOMBO, CB_GETCURSEL, 0, 0);
        if (HIWORD(wParam) == CBN_SELCHANGE)
            if (proxynr1 == (int)SendDlgItemMessage(hWnd, IDC_PROXYCOMBO, CB_GETCOUNT, 0, 0) - 1)
                PostMessage(hWnd, WM_COMMAND, IDC_PROXYBUTTON, 0);
        break;
    }
    case IDC_PROXYBUTTON:
    {
        int proxynr = (int)SendDlgItemMessage(hWnd, IDC_PROXYCOMBO, CB_GETCURSEL, 0, 0);
        if (proxynr > 0) {
            gProxyNr = proxynr;
            if (IDOK == DialogBox(hinst, MAKEINTRESOURCE(IDD_PROXY), GetActiveWindow(), ProxyDlgProc))
                fillProxyCombobox(hWnd, proxynr);
        }
        break;
    }
    case IDC_KEEP_ALIVE:
        ::EnableWindow(GetDlgItem(hWnd,IDC_KEEP_ALIVE_SECONDS), IsDlgButtonChecked(hWnd, IDC_KEEP_ALIVE));
        if (IsDlgButtonChecked(hWnd, IDC_KEEP_ALIVE))
            ::SetFocus(GetDlgItem(hWnd, IDC_KEEP_ALIVE_SECONDS));
        break;
    case IDC_DELETELAST:
    {
        int proxynr = (int)SendDlgItemMessage(hWnd, IDC_PROXYCOMBO, CB_GETCOUNT, 0, 0) - 2;
        if (proxynr >= 2) {    // proxy nr 1 cannot be deleted!
            CHAR errorstr[1024];
            LoadString(hinst, IDS_ERROR_INUSE, errorstr, sizeof(errorstr));
            strlcat(errorstr, "\n", sizeof(errorstr)-1);
            if (DeleteLastProxy(proxynr, gConnectResults->DisplayName, errorstr, sizeof(errorstr)-1)) {
                int proxynr = (int)SendDlgItemMessage(hWnd, IDC_PROXYCOMBO, CB_GETCURSEL, 0, 0);
                fillProxyCombobox(hWnd, proxynr);
            } else {
                MessageBox(hWnd, errorstr, "SFTP", MB_ICONSTOP);   
            }
        } else
            MessageBeep(MB_ICONSTOP);   // FIXME: ????????
        break;
    }
    default:
        return -1;
    } /* switch(ctrl) */
    hr = 0;
fin:
    return hr;
}

bool Dialog::is_checked(int idc)
{
    return (IsDlgButtonChecked(m_wnd, idc) == BST_CHECKED) ? true : false;
}

bool Dialog::wm_command_ok()
{
#ifdef WFX_DEBUG
    //m_cfg.set_debug_level(get_combobox_seleted_data(IDC_DEBUG_LEVEL));
    //WcxSetLogLevel(m_cfg.get_debug_level());
#endif
    /*
    m_cfg.set_compression_level(get_compression_level());
  
    m_cfg.set_cache_lifetime(get_combobox_seleted_data(IDC_CACHE_TIME));
    {
        int flags = 0;
        flags |= is_checked(IDC_LBL_SAVE_CREATE_TIME) ? cfg::save_ctime : 0;
        flags |= is_checked(IDC_LBL_SAVE_ACCESS_TIME) ? cfg::save_atime : 0;
        m_cfg.set_file_time(flags);
    }
    {
        int flags = 0;
        flags |= is_checked(IDC_LBL_SAVE_READONLY)    ? cfg::save_readonly : 0;
        flags |= is_checked(IDC_LBL_SAVE_HIDDEN)      ? cfg::save_hidden   : 0;
        flags |= is_checked(IDC_LBL_SAVE_SYSTEM)      ? cfg::save_system   : 0;
        flags |= is_checked(IDC_LBL_SAVE_ARCHIVE)     ? cfg::save_archive  : 0;
        m_cfg.set_file_attr(flags);
    }
    */
    return false;
}

} /* namespace */

