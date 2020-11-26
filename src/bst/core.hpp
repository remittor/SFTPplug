#pragma once

#include <windows.h>
#include "config.hpp"
#include <stdexcept>
#include <vadefs.h>

#ifndef BST_MAX_EX_MSG_LEN
#define BST_MAX_EX_MSG_LEN  1024
#endif

#define BST_THROW_SAVE_FILENAME

#ifdef _DEBUG
#define BST_INLINE 
#define BST_FORCEINLINE 
#else
#define BST_INLINE       __forceinline
#define BST_FORCEINLINE  __forceinline
#endif

#define BST_NOINLINE     __declspec(noinline)

#define BST_NOTHROW      __declspec(nothrow)

#define BST_MAX(a,b)    (((a) > (b)) ? (a) : (b))
#define BST_MIN(a,b)    (((a) < (b)) ? (a) : (b))

// Synthesize a unique symbol.
#define _BST_MKID(x, y) x ## y
#define BST_MKID(x, y) _BST_MKID(x, y)
#define BST_GENSYM(x) BST_MKID(x, __COUNTER__)

#ifdef _M_X64
#define BST_VA_START(ap, x)  ((void)(__va_start(&ap, x)))
#else
#define BST_VA_START(ap, x)  va_start(ap, x)
#endif

#define BST_ARGS template<typename ... Args>


namespace bst {

enum class error_t : char {
    non_error = 0,
    internal  = 1,
    usual     = 2,
    critical  = 3,
    fatal     = 4,
};

namespace err {
    const error_t I = error_t::internal;
    const error_t U = error_t::usual;
    const error_t C = error_t::critical;
    const error_t F = error_t::fatal;
}


class exception : public std::exception
{
protected:
    const char * m_filename = nullptr;
    const char * m_funcname = nullptr;
    char       * m_messageA = nullptr;
    wchar_t    * m_messageW = nullptr;
    int          m_err_code = 0;
    error_t      m_err_type = error_t::non_error;

    void init(error_t err_type, LPCSTR filename, LPCSTR funcname, int err_code, LPCSTR msgA, LPCWSTR msgW) noexcept
    {
        copy(true, err_type, filename, funcname, err_code, msgA, msgW);
    }

public:
    exception() noexcept = default;

    explicit exception(error_t err_type, LPCSTR filename, LPCSTR funcname, int err_code, LPCSTR message, ...) noexcept
    {
        va_list argptr;
        va_start(argptr, message);
        assign(err_type, filename, funcname, err_code, message, argptr);
        va_end(argptr);
    }

    explicit exception(error_t err_type, LPCSTR filename, LPCSTR funcname, int err_code, LPCWSTR message, ...) noexcept
    {
        va_list argptr;
        va_start(argptr, message);
        assign(err_type, filename, funcname, err_code, message, argptr);
        va_end(argptr);
    }

    exception(const exception & ex) noexcept
    {
        init(ex.m_err_type, ex.m_filename, ex.m_funcname, ex.m_err_code, ex.m_messageA, ex.m_messageW);
    }

    exception(const std::exception & ex) noexcept
    {
        init(error_t::critical, nullptr, nullptr, 0, ex.what(), nullptr);
    }

    exception & operator = (const std::exception & ex) noexcept
    {
        copy(false, error_t::critical, nullptr, nullptr, 0, ex.what(), nullptr);
        return *this;
    }

    exception & operator = (const exception & ex) noexcept
    {
        copy(false, ex.m_err_type, ex.m_filename, ex.m_funcname, ex.m_err_code, ex.m_messageA, ex.m_messageW);
        return *this;
    }

    exception(exception && ex) noexcept
    {
        m_filename = ex.m_filename;
        m_funcname = ex.m_funcname;
        m_messageA = ex.m_messageA;
        m_messageW = ex.m_messageW;
        m_err_code = ex.m_err_code;
        m_err_type = ex.m_err_type;
        ex.m_messageA = nullptr;
        ex.m_messageW = nullptr;
    }

    virtual ~exception() noexcept
    {
        clear();
    }

    void clear(error_t err_type = error_t::non_error)
    {
        ::free(m_messageA);
        ::free(m_messageW);
        m_filename = nullptr;
        m_funcname = nullptr;
        m_messageA = nullptr;
        m_messageW = nullptr;
        m_err_code = 0;
        m_err_type = err_type;
    }

    virtual error_t error_type() const noexcept
    {
        return m_err_type;
    }

    virtual int error_code() const noexcept
    {
        return m_err_code;
    }

    virtual const char * what() const noexcept
    {
        return m_messageA;
    }

    virtual const wchar_t * whatW() const noexcept
    {
        return m_messageW;
    }

    const char * filename() const noexcept
    {
        return m_filename;
    }

    const char * funcname() const noexcept
    {
        return m_funcname;
    }

protected:
    BST_NOINLINE
    void assign(error_t err_type, LPCSTR filename, LPCSTR funcname, int err_code, LPCSTR message, va_list argptr) noexcept
    {
        if (message == nullptr) {
            init(err_type, filename, funcname, err_code, nullptr, nullptr);
            return;
        }
        if (strchr(message, '%') == nullptr) {
            init(err_type, filename, funcname, err_code, message, nullptr);
            return;
        }
        init(err_type, filename, funcname, err_code, nullptr, nullptr);
        m_messageA = (char *) ::malloc(BST_MAX_EX_MSG_LEN + 2);
        if (m_messageA) {
            int len = vsprintf_s(m_messageA, BST_MAX_EX_MSG_LEN, message, argptr);
            m_messageA[(len < 0) ? 0 : len] = 0;
        }
    }

    BST_NOINLINE
    void assign(error_t err_type, LPCSTR filename, LPCSTR funcname, int err_code, LPCWSTR message, va_list argptr) noexcept
    {
        if (message == nullptr) {
            init(err_type, filename, funcname, err_code, nullptr, nullptr);
            return;
        }
        if (wcschr(message, L'%') == nullptr) {
            init(err_type, filename, funcname, err_code, nullptr, message);
            return;
        }
        init(err_type, filename, funcname, err_code, nullptr, nullptr);
        m_messageW = (wchar_t *) ::malloc((BST_MAX_EX_MSG_LEN + 2) * sizeof(wchar_t));
        if (m_messageW) {
            int len = vswprintf_s(m_messageW, BST_MAX_EX_MSG_LEN, message, argptr);
            m_messageW[(len < 0) ? 0 : len] = 0;
        }
    }

    BST_NOINLINE
    void copy(bool init, error_t err_type, LPCSTR filename, LPCSTR funcname, int err_code, LPCSTR msgA, LPCWSTR msgW) noexcept
    {
        if (!init) {
            ::free(m_messageA);
            ::free(m_messageW);
        }
        m_filename = filename;
        m_funcname = funcname;
        m_messageA = nullptr;
        m_messageW = nullptr;
        m_err_code = err_code;
        m_err_type = err_type;
        if (msgA) {
            size_t len = strlen(msgA) + 1;
            m_messageA = (char *) ::malloc(len);
            if (m_messageA)
                memcpy(m_messageA, msgA, len);
        }
        if (msgW) {
            size_t len = wcslen(msgW) + 1;
            m_messageW = (wchar_t *) ::malloc(len * sizeof(wchar_t));
            if (m_messageW)
                memcpy(m_messageW, msgW, len * sizeof(wchar_t));
        }
    }
};


template <error_t ET>
class exception_base : public exception
{
    friend class exception;
public:
    exception_base() noexcept
    {
        m_err_type = ET;
    }

    explicit exception_base(LPCSTR filename, LPCSTR funcname, int err_code, LPCSTR message, ...) noexcept
    {
        va_list argptr;
        va_start(argptr, message);
        assign(ET, filename, funcname, err_code, message, argptr);
        va_end(argptr);
    }

    explicit exception_base(LPCSTR filename, LPCSTR funcname, int err_code, LPCWSTR message, ...) noexcept
    {
        va_list argptr;
        va_start(argptr, message);
        assign(ET, filename, funcname, err_code, message, argptr);
        va_end(argptr);
    }
};

} /* namespace bst */


#ifdef BST_THROW_SAVE_FILENAME

#define BST_THROW(_et_,_err_,_msg_,...) \
    throw bst::exception_base<bst::err::_et_>(__FILE__, __func__, _err_, _msg_, __VA_ARGS__)

#define BST_THROW_IF(_cond_,_et_,_err_,_msg_,...) \
    if (_cond_) throw bst::exception_base<bst::err::_et_>(__FILE__, __func__, _err_, _msg_, __VA_ARGS__)

#else

#define BST_THROW(_et_,_err_,_msg_,...) \
    throw bst::exception_base<bst::err::_et_>(nullptr, __func__, _err_, _msg_, __VA_ARGS__)

#define BST_THROW_IF(_cond_,_et_,_err_,_msg_,...) \
    if (_cond_) throw bst::exception_base<bst::err::_et_>(nullptr, __func__, _err_, _msg_, __VA_ARGS__)

#endif

