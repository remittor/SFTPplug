#include "excatch.h"
#include "StackWalker.h"
#include <shellapi.h>

namespace wfx {

static const int max_stack_depth = 13;
static const int swoptions = StackWalkerBase::RetrieveVerbose;

class StackWalker final : public StackWalkerBase
{
    friend class StackWalkerBase;
public:
    bst::nt::str & m_trace;
    int m_max_depth;
    int m_cur_depth;

    enum { MAX_NAMELEN = 2048 };

    StackWalker() = delete;

    StackWalker(bst::nt::str & trace, int depth = max_stack_depth) noexcept
      : StackWalkerBase(swoptions)
      , m_trace(trace)
    {
        m_max_depth = depth;
        m_cur_depth = 0;
    }

protected:
    virtual void OnCallstackEntry(const TCallstackEntry & entry) noexcept
    {
        CHAR buffer[MAX_NAMELEN];
        if ((entry.type != lastEntry) && (entry.offset != 0)) {
            TCallstackEntry e = entry;
            if (!e.moduleName || e.moduleName[0] == 0)
                e.moduleName = "[<module>]";
            if (!e.name || e.name[0] == 0)
                e.name = "(function-name not available)";
            if (e.undName && e.undName[0] != 0)
                e.name = entry.undName;
            if (e.undFullName && e.undFullName[0] != 0)
                e.name = e.undFullName;
            if (!e.lineFileName || e.lineFileName[0] == 0) {
                _snprintf_s(buffer, _TRUNCATE, "%p (%s): %s\n", (LPVOID)e.offset, e.moduleName, e.name);
            } else {
                _snprintf_s(buffer, _TRUNCATE, "%p (%s): %s (%d): %s\n", (LPVOID)e.offset, e.moduleName, e.lineFileName, e.lineNumber, e.name);
            }
            buffer[_countof(buffer)-1] = 0;
            OnOutput(buffer);
        }
    }

    virtual void OnOutput(LPCSTR szText) noexcept
    {
        if (m_cur_depth <= m_max_depth) {
            if (m_cur_depth == 0)
                LOGc("<<< CRITICAL ERROR >>>  StackTrace: \n");
            m_cur_depth++;
            LOGc("  %s", szText);
            m_trace.append(szText);
        }
    }

    virtual void OnShowObject(const TShowObject & data) noexcept
    {
        // nothing
    }

    virtual void OnLoadDbgHelp(const TLoadDbgHelp & data) noexcept
    {
        // nothing
    }

    virtual void OnLoadModule(const TLoadModule & data) noexcept
    {
        // nothing
    }

    virtual void OnSymInit(const TSymInit & data) noexcept
    {
        // nothing
    }

    virtual void OnDbgHelpErr(const TDbgHelpErr & data) noexcept
    {
        // nothing
    }
};

void ExCatcher::init(LPVOID * pctx) noexcept
{
    m_active = true;
    try {
        throw;
    }
    catch (bst::exception & ex) {
        m_cppex = ex;
    }
    catch (std::exception & ex) {
        m_cppex = ex;
    }
    catch (...) {
        m_cppex = bst::exception_base<bst::error_t::fatal>(nullptr, nullptr, 0, "Unknown fatal error");
    }

    if (pctx) {
        PCONTEXT ctx = *(PCONTEXT *)pctx;
        if (ctx) {
            m_trace.reserve(max_stack_depth * StackWalker::MAX_NAMELEN);
            StackWalker sw(m_trace);
            sw.ShowCallstack(GetCurrentThread(), ctx);
        }
    }
}

int ExCatcher::show(LPCWSTR fmt, ...)
{
    bst::nt::static_wstr<2000> msg;
    if (m_active && !m_showed) {
        m_showed = true;
        int err_level = BST_LL_ERROR;
        LPCSTR error_level = "";
        switch (m_cppex.error_type()) {
            case (bst::error_t::critical) : {
                err_level = BST_LL_CRIT_ERROR;
                error_level = "CRITICAL";
                break;
            }
            case (bst::error_t::fatal) : {
                err_level = BST_LL_FATAL_ERROR;
                error_level = "FATAL";
                break;
            }
        }
        LOGX(err_level, "<<< %s ERROR >>>", error_level);
        if (m_cppex.funcname()) {
            LOGX(err_level, "  Filename: %s", m_cppex.filename());
            LOGX(err_level, "  Function: %s", m_cppex.funcname());
            LOGX(err_level, "  Error Code: %d (0x%08X) \n", m_cppex.error_code(), m_cppex.error_code());
        }
        LOGX(err_level, "  Error: %s", m_cppex.what());
        if (fmt) {
            va_list argptr;
            va_start(argptr, fmt);
            int x = vswprintf_s(msg.data(), msg.capacity(), fmt, argptr);
            msg.fix_length();
            WLOGX(err_level, L"  Message: %s", msg.c_str());
        }
        if (err_level < BST_LL_ERROR) {
            bst::nt::static_wstr<4000> txt;
            bst::nt::filename caption;
            caption.assign(CP_ACP, error_level);
            caption.append(L" ERROR ");
            if (m_cppex.whatW()) {
                txt.append_fmt(L"Error: %s \n", m_cppex.whatW());
            } else {
                txt.append_fmt(L"Error: %S \n", m_cppex.what());
            }
            if (m_cppex.funcname()) {
                txt.append(L"\n");
                txt.append_fmt(L"Error Code: %d (0x%08X) \n", m_cppex.error_code(), m_cppex.error_code());
                txt.append_fmt(L"Filename: %S \n", m_cppex.filename());
                txt.append_fmt(L"Function: %S \n", m_cppex.funcname());
            }
            if (msg.length()) {
                txt.append_fmt(L"Message: %s \n", msg.c_str());
            }
            if (m_trace.length()) {
                txt.append(L"\n");
                txt.append_fmt(L"StackTrace:\n%S\n", m_trace.c_str());
            }
            //::MessageBoxW(GetActiveWindow(), txt.c_str(), caption.c_str(), MB_OK | MB_ICONERROR);
            ::ShellMessageBoxW(NULL, GetActiveWindow(), txt.c_str(), caption.c_str(), MB_OK | MB_ICONERROR);
        }
    }
    return 0;
}

} /* namespace */

