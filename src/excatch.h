#pragma once

#include "utils.h"
#include "sftpplug.h"
#include <stdexcept>


namespace wfx {

class ExCatcher : bst::NonCopyableNonMoveable
{
protected:
    Plugin         & m_plg;
    bst::exception   m_cppex;   // C++ exception info
    bst::nt::str     m_trace;   // stack trace
    bool             m_active = false;
    bool             m_showed = false;

public:
    ExCatcher() noexcept = delete;

    explicit ExCatcher(Plugin & plg) noexcept
      : m_plg(plg)
    {
        //
    }

    ~ExCatcher()
    {
        show(nullptr);
    }

    void init() noexcept;
    int  show(LPCWSTR fmt, ...);

    bool is_active() { return m_active; }
    bool is_showed() { return m_showed; }
};

/* C++ and SEH catcher (required /EHa option) */
template<typename R, typename F>
auto invoke(ExCatcher & exc, R eval, F && func)
{
    try {
        return func();
    }
    catch (...) {
        exc.init();
    }
    return eval;
}

} /* namespace */
