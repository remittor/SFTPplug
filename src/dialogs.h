#pragma once

#include <windows.h>
#include "bst\string.hpp"
#include "bst\log.hpp"
#include "version.h"
#include "cfg.h"


namespace wfx {

class Dialog
{
public:
    friend class Cfg;
    friend class Plugin;

    Dialog() = delete;
    Dialog(wfx::Plugin & plg, wfx::IniCfg & ini, bst::c_str & name);
    ~Dialog();

    LPCWSTR get_control_name(int idc, bst::wsfn & name, LPCWSTR default_name = NULL);

    //void set_file_time_checkbox(cfg::AttrTime flags);
    //void set_file_attr_checkbox(cfg::AttrFile flags);

    int show();

    bool wm_destroy();
    bool translate();
    bool wm_init(HWND hwndDlg, WPARAM wParam);
    //int wm_control_color_static(HWND wnd, HDC hdc);
    bool wm_command(UINT16 ctrl, UINT16 val);
    bool wm_command_ok();
  
    wfx::Cfg & get_cfg() { return m_cfg; }
    int get_result() { return m_result; }
  
public:
    bool set_button_check(int idc, int checked);
    int combobox_add(int idc, LPCWSTR txt, int data);
    int combobox_add(int idc, int data);
    int get_combobox_seleted_data(int idc);
    bool is_checked(int idc);
    int get_compression_level();
    bool show_control(int idc);
    bool enable_controls();
    bool update_combos();
    void set_combobox_height(int idc, int nItems);
    void EnableControlsPageant(bool enable = true);
    bool SetDialogPosToCenter(DWORD dwFlags = SWP_NOZORDER | SWP_NOSIZE);
    bool get_item_text(int idc, bst::str & text);
    bool is_button_checked(int idc);

    wfx::Plugin & m_plg;
    bst::str   m_name;
    wfx::IniCfg & m_ini;
    wfx::Cfg   m_cfg;
    HMODULE    m_dll;
    HWND       m_parent_wnd;
    HWND       m_wnd;
    int        m_idc;          // dialog ID
    //HFONT      m_hBoldFont;
    HFONT      m_hFixedFont;
    int        m_result;       // IDOK or IDCANCEL

    bool m_server_field_changed_by_user;
};

} /* namespace */

