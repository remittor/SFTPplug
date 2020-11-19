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
    bst::str         m_trace;   // stack trace
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

    int init(const std::exception & ex) noexcept;
    int init(const bst::exception & ex) noexcept;
    int init(PEXCEPTION_POINTERS pExp, DWORD dwExpCode) noexcept;
    int show(LPCWSTR fmt, ...);

    bool is_active() { return m_active; }
    bool is_showed() { return m_showed; }

protected:
    int init_cpp_internal() noexcept;
};


/* CPP exception catcher */
template<typename R, typename F>
auto catch_cpp_exceptions(ExCatcher & exc, R eval, F && func)
{
    try {
        return func();
    }
    catch (bst::exception & ex) {
        exc.init(ex);
        throw;
    }
    catch (std::exception & ex) {
        exc.init(ex);
        throw;
    }
    return eval;
}

/* SEH catcher */
template<typename R, typename F>
auto invoke(ExCatcher & exc, R eval, F && func)
{
    __try {
        return catch_cpp_exceptions(exc, eval, std::forward<F>(func));
    }
    __except ( exc.init(GetExceptionInformation(), GetExceptionCode()) ) {
        // nothing
    }
    return eval;
}


} /* namespace */
