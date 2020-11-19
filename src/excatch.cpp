#include "excatch.h"

namespace wfx {

int ExCatcher::init(const std::exception & ex) noexcept
{
    m_active = true;
    m_cppex = ex;
    return init_cpp_internal();
}

int ExCatcher::init(const bst::exception & ex) noexcept
{
    m_active = true;
    m_cppex = ex;
    return init_cpp_internal();
}

int ExCatcher::init_cpp_internal() noexcept
{
    m_active = true;
    LOGf("%s: ", __func__);
    return 0;
}

int ExCatcher::init(PEXCEPTION_POINTERS pExp, DWORD dwExpCode) noexcept
{
    m_active = true;
    //StackWalker sw;
    //sw.ShowCallstack(GetCurrentThread(), pExp->ContextRecord);
    LOGf("%s: %d (%p) ", __func__, dwExpCode, pExp);
    return EXCEPTION_EXECUTE_HANDLER;
}

int ExCatcher::show(LPCWSTR fmt, ...)
{
    if (m_active && !m_showed) {
        m_showed = true;
        LOGf("%s: <FATAL>: (%d) %s", __func__, m_cppex.error_code(), m_cppex.what());
    }
    return 0;
}

} /* namespace */

