#pragma once

#include "bst.hpp"
#include <cstdlib>
#include <shlwapi.h>
#include <stdio.h>
#include <vadefs.h>

namespace bst {

static const size_t npos = (size_t)(-1);    /* Non-position */

enum error_code : char {
    non_error        = 0,
    e_out_of_memory  = 2,
    e_out_of_range   = 3,
    e_convert        = 4,
    e_max_code       = 5,
};

enum class codepage_t : int {
    utf16    = -2,
    us_ascii = -1,
    acp      = CP_ACP,       // ANSI (active code page)
    utf8     = CP_UTF8,
};


template <typename CharT>
class fmt_string
{
private:
    const CharT * m_ptr;
public:  
    fmt_string() = delete;
    fmt_string(const CharT & s) noexcept { m_ptr = s; }
    ~fmt_string() = default;
    explicit fmt_string(const CharT * s) noexcept { m_ptr = s; }
    const CharT * c_str() const noexcept { return m_ptr; }
};

template <typename CharT>
BST_FORCEINLINE const fmt_string<CharT> fmtstr(const CharT * s)
{
    return fmt_string<CharT>(s);
}


namespace detail {

template <typename CharT, bool NT = false>      /* NT = nothrow */
class string_base
{
protected:
    CharT    * m_buf;
    size_t     m_len;
    size_t     m_capacity;
    bool       m_is_static;
    error_code m_last_error;

    enum { is_string  = std::is_same<CharT, char>::value };
    enum { is_wstring = std::is_same<CharT, wchar_t>::value };
    enum { is_buffer  = std::is_same<CharT, UCHAR>::value };

    BST_FORCEINLINE
    void set_defaults() noexcept
    {
        m_buf = nullptr;
        m_len = 0;
        m_capacity = 0;
        m_is_static = false;
        m_last_error = non_error;
    }

public:
    typedef CharT * pointer;
    typedef const CharT * const_pointer;
    typedef CharT & reference;
    typedef const CharT & const_reference;

    enum char_case {
        case_insensitive = 0,
        case_sensitive   = 1,    
    };

    string_base() noexcept
    {
        set_defaults();
    }

    string_base(const CharT * s, size_t len = 0) noexcept(NT)
    {
        set_defaults();
        assign(s, len);
    }

    string_base(const fmt_string<CharT> fmt, ...) noexcept(NT)
    {
        set_defaults();
        va_list argptr;
        va_start(argptr, fmt);
        assign_fmt_internal(fmt.c_str(), argptr);
        va_end(argptr);
    }

    ~string_base() noexcept
    {
        destroy();
    }

    /* copy-constructor */
    string_base(const string_base & str) noexcept(NT)
    {
        set_defaults();
        assign(str.m_buf, str.m_len);
    }

    /* move-constructor */
    string_base(string_base && str) noexcept
    {
        m_buf = str.m_buf;
        m_len = str.m_len;
        m_capacity = str.m_capacity;
        m_is_static = str.m_is_static;
        m_last_error = str.m_last_error;
    }

    bool is_static() const noexcept
    {
        return m_is_static;
    }

    constexpr bool is_nothrow() const noexcept
    {
        return NT;
    }

    error_code get_last_error(bool reset = true) noexcept
    {
        error_code err_code = m_last_error;
        if (reset)
            m_last_error = non_error;
        return err_code;
    }

    bool has_error(bool reset = true) noexcept
    {
        return get_last_error(reset) != non_error;
    }

    void clear() noexcept
    {
        m_len = 0;
        if (m_buf)
            m_buf[0] = 0;
    }

    void destroy() noexcept
    {
        clear();
        if (!is_static()) {
            free(m_buf);
            m_buf = nullptr;
            m_capacity = 0;
        }
    }

    static size_t get_length(const CharT * s) noexcept
    {
        size_t len = 0;
        if (s)
            while (*s++) len++;
        return len;
    }

    /* possible return npos */
    size_t fix_length() noexcept
    {
        if (m_capacity && m_buf) {
            m_buf[m_capacity] = 0;
            m_len = get_length(m_buf);
            return m_len;
        }
        return npos;
    }

    bool assign(const CharT * s, size_t len = 0) noexcept(NT)
    {
        return assign_internal(s, len);
    }

    bool assign(const string_base & str) noexcept(NT)
    {
        return assign_internal(str.c_str(), str.length());
    }

    bool reserve(size_t len) noexcept(NT)
    {
        return set_capacity(len, true);
    }

    size_t length() const
    {
        return m_len;
    }

    size_t size() const 
    {
        return m_len;
    }

    size_t size_bytes() const
    {
        return m_len * sizeof(CharT);
    }

    size_t capacity() const
    {
        return m_capacity;
    }

    size_t capacity_bytes() const
    {
        return m_capacity * sizeof(CharT);
    }

    bool empty() const
    {
        return m_len == 0;
    }

    bool is_null() const
    {
        return m_buf == nullptr;
    }

    void * ptr()
    {
        return (void *)m_buf;
    }

    const void * c_ptr() const
    {
        return (const void *)m_buf;
    }

    CharT * data()
    {
        return m_buf;
    }

    const CharT * c_data() const
    {
        return m_buf;
    }

    const CharT * c_str() const
    {
        return m_buf;
    }

    CharT & at(size_t pos) noexcept(NT)
    {
        BST_THROW_IF(!NT && pos >= m_len, C, 1, "bad string pos");
        return m_buf[pos];
    }

    const CharT & at(size_t pos) const noexcept(NT)
    {
        BST_THROW_IF(!NT && pos >= m_len, C, 1, "bad string pos");
        return m_buf[pos];
    }

    CharT & back() noexcept(NT)
    {
        BST_THROW_IF(!NT && m_len == 0, C, 2, "bad string pos");
        return (m_buf && m_len > 0) ? m_buf[m_len - 1] : 0;
    }

    const CharT & back() const noexcept(NT)
    {
        BST_THROW_IF(!NT && m_len == 0, C, 2, "bad string pos");
        return (m_buf && m_len > 0) ? m_buf[m_len - 1] : 0;
    }

    CharT & front() noexcept(NT)
    {
        BST_THROW_IF(!NT && m_len == 0, C, 3, "bad string pos");
        return (m_buf && m_len > 0) ? m_buf[0] : 0;
    }

    const CharT & front() const noexcept(NT)
    {
        BST_THROW_IF(!NT && m_len == 0, C, 3, "bad string pos");
        return (m_buf && m_len > 0) ? m_buf[0] : 0;
    }

    /* possible return npos */
    size_t resize(size_t len) noexcept(NT)
    {
        return resize_internal(len, false, 0);
    }

    size_t resize(size_t len, CharT c) noexcept(NT)
    {
        return resize_internal(len, true, c);
    }

    /* possible return null */
    CharT * expand(size_t add_len) noexcept(NT)
    {
        if (add_len == 0)
            return m_buf ? &m_buf[m_len] : nullptr;

        if (resize(m_len + add_len, 0) == npos)
            return nullptr;

        return &m_buf[m_len];
    }

    string_base & append(const CharT * s, size_t slen = 0) noexcept(NT)
    {
        append_internal(s, slen);
        return *this;
    }

    string_base & append(const string_base & str) noexcept(NT)
    {
        append_internal(str.c_data(), str.length());
        return *this;
    }

    /* possible return npos */
    size_t copy(CharT * s, size_t len, size_t pos = 0) const noexcept(NT)
    {
        if (!s || pos >= m_len) {
            BST_THROW_IF(!NT, C, 5, "bad string pos");
            return npos;
        }
        if (!m_buf)
            len = 0;

        if (pos + len > m_len)
            len = m_len - pos;

        if (len > 0)
            memcpy(s, &m_buf[pos], len * sizeof(CharT));

        if (!is_buffer)
            s[len] = 0;

        return len;
    }

    string_base & operator = (const string_base & str) noexcept(NT)
    {
        assign(str);
        return *this;
    }

    string_base & operator = (const CharT * s) noexcept(NT)
    {
        assign(s);
        return *this;
    }

    string_base & operator += (const string_base & str) noexcept(NT)
    {
        append(str);
        return *this;
    }

    string_base & operator += (const CharT * s) noexcept(NT)
    {
        append(s);
        return *this;
    }

    CharT & operator [] (size_t pos) noexcept(NT)
    {
        return at(pos);
    }

    const CharT & operator [] (size_t pos) const noexcept(NT)
    {
        return at(pos);
    }

protected:
    BST_NOINLINE
    size_t request_length(size_t new_len, size_t suffix = 0, bool save_data = true) noexcept(NT)
    {
        if (is_static()) {
            if (new_len > m_capacity) {      /* ignore suffix for static string */
                m_last_error = e_out_of_range;
                BST_THROW_IF(!NT, C, 200, "Bad string growth");
                return m_capacity;
            }
        } else {
            if (!m_buf || new_len + suffix > m_capacity)
                if (!set_capacity(new_len + suffix, save_data))
                    return npos;
        }  
        return new_len;
    }

    BST_NOINLINE
    bool set_capacity(size_t new_capacity, bool save_data) noexcept(NT)
    {
        if (new_capacity <= m_capacity)
            return true;

        if (is_static()) {
            m_last_error = e_out_of_range;
            BST_THROW_IF(!NT, C, 201, "Bad string growth");
            return false;
        }
        else {
            CharT * buf = (CharT *) malloc((new_capacity + 2) * sizeof(CharT));
            if (!buf) {
                m_last_error = e_out_of_memory;
                BST_THROW_IF(!NT, C, 202, "Bad string growth");
                return false;
            }
            buf[0] = 0;
            if (m_buf) {
                if (m_len && save_data) {
                    memcpy(buf, m_buf, (m_len + 1) * sizeof(CharT));
                }
                delete[] m_buf;
            }
            m_buf = buf;
            m_capacity = new_capacity;
        }
        return true;
    }

    BST_NOINLINE
    size_t resize_internal(size_t len, bool fill, CharT c) noexcept(NT)
    {
        if (len <= m_len) {
            if (!is_buffer && m_buf)
                m_buf[len] = 0;
            m_len = len;
            return len;
        } 
        len = request_length(len);
        if (len == npos)
            return len;

        if (!is_buffer && !fill) {
            fill = true;
            c = 0;
        }
        if (fill) {
            for (size_t i = m_len; i < len; i++) {
                m_buf[i] = c;
            }
        }  
        if (!is_buffer)
            m_buf[len] = 0;

        m_len = len;
        return len;
    }

    BST_FORCEINLINE
    static size_t decode_data_len(const CharT * s, size_t slen, bool is_null_terminated)
    {
        if (!is_null_terminated || (SSIZE_T)slen > 0)
            return slen;
        if (!s)
            return 0;
        return get_length(s);
    }

    BST_NOINLINE
    bool assign_internal(const CharT * s, size_t len = 0) noexcept(NT)
    {
        if (!s) {
            destroy();
            return true;
        }
        clear();
        return append_internal(s, len, 0);
    }

    BST_NOINLINE
    bool assign_fmt_internal(const CharT * fmt, va_list args) noexcept(NT)
    {
        if (!s) {
            destroy();
            return true;
        }
        clear();
        return append_fmt_internal(fmt, args, 0);
    }

    BST_NOINLINE
    bool append_internal(const CharT * s, size_t slen = 0, size_t suffix = 64) noexcept(NT)
    {
        if (!s)
            return true;

        slen = decode_data_len(s, slen, !is_buffer);
        if (slen == 0)
            return true;

        size_t len = request_length(m_len + slen, 64);
        if (len == npos)
            return false;

        if (len > m_len) {
            memcpy(&m_buf[m_len], s, (len - m_len) * sizeof(CharT));
            m_len = len;
            if (!is_buffer)
                m_buf[m_len] = 0;
        }
        return true;
    }

    BST_NOINLINE
    bool append_fmt_internal(const CharT * fmt, va_list args, size_t suffix = 64) noexcept(NT)
    {
        if (!fmt)
            return true;

        size_t flen = get_length(fmt);
        if (flen == 0)
            return true;

        SSIZE_T slen;
        if (is_wstring)
            slen = _vscwprintf((LPCWSTR)fmt, args);
        else
            slen = _vscprintf((LPCSTR)fmt, args);

        if (slen < 0) {
            m_last_error = e_convert;
            BST_THROW_IF(!NT, C, 100, "Incorrect format-control string");
            return false;
        }
        if (slen == 0)
            return true;

        slen += 1;
        size_t len = request_length(m_len + slen, suffix);
        if (len == npos)
            return false;

        SSIZE_T sz;
        if (is_wstring)
            sz = vswprintf_s((LPWSTR)m_buf + m_len, slen, (LPCWSTR)fmt, argptr);
        else
            sz = vsprintf_s((LPSTR)m_buf + m_len, slen, (LPCSTR)fmt, argptr);

        if (sz <= 0 || m_len + sz > m_capacity) {
            m_last_error = e_convert;
            BST_THROW_IF(!NT, C, 101, "Incorrect format-control string");
            return false;
        }
        m_len += sz;
        m_buf[m_len] = 0;
        return true;
    }

public:
    size_t rfind(const string_base & str, size_t pos = npos) const noexcept
    {
        return rfind_internal(str.c_str(), str.length(), pos, case_sensitive);
    }

    size_t rfind(const CharT * s, size_t pos = npos) const noexcept
    {
        return rfind_internal(s, 0, pos, case_sensitive);
    }

    size_t rfind_i(const string_base & str, size_t pos = npos) const noexcept
    {
        return rfind_internal(str.c_str(), str.length(), pos, case_insensitive);
    }

    size_t rfind_i(const CharT * s, size_t pos = npos) const noexcept
    {
        return rfind_internal(s, 0, pos, case_insensitive);
    }

protected:
    BST_NOINLINE
    size_t rfind_internal(const CharT * s, size_t slen, size_t pos, char_case _case) const noexcept
    {
        if (is_buffer)
            return npos;

        slen = decode_data_len(s, slen, !is_buffer);
        if (slen == 0 || empty() || (pos != npos && pos > length()))
            return npos;

        const_pointer last = (pos == npos) ? nullptr : m_buf + pos;

        size_t res;
        if (is_wstring)
            res = (size_t)StrRStrIW((LPCWSTR)m_buf, (LPCWSTR)last, (LPCWSTR)s);
        else
            res = (size_t)StrRStrIA((LPCSTR)m_buf, (LPCSTR)last, (LPCSTR)s);

        return (!res) ? npos : (res - (size_t)m_buf) / sizeof(CharT);
    }   

public:
    size_t rfind(const CharT c, size_t pos = npos) const noexcept
    {
        return rfind_internal(c, pos, case_sensitive);
    }

    size_t rfind_i(const CharT c, size_t pos = npos) const noexcept
    {
        return rfind_internal(c, pos, case_insensitive);
    }

protected:
    BST_NOINLINE
    size_t rfind_internal(const CharT c, size_t pos, char_case _case) const noexcept
    {
        if (is_buffer)
            return npos;

        if (empty() || (pos != npos && pos > length()))
            return npos;

        const_pointer end = (pos == npos) ? nullptr : m_buf + pos;

        size_t res;
        if (_case == case_sensitive) {
            if (is_wstring)
                res = (size_t)StrRChrW((LPCWSTR)m_buf, (LPCWSTR)end, (WCHAR)c);
            else
                res = (size_t)StrRChrA((LPCSTR)m_buf, (LPCSTR)end, (CHAR)c);
        } else {
            if (is_wstring)
                res = (size_t)StrRChrIW((LPCWSTR)m_buf, (LPCWSTR)end, (WCHAR)c);
            else
                res = (size_t)StrRChrIA((LPCSTR)m_buf, (LPCSTR)end, (CHAR)c);
        }  
        return (!res) ? npos : (res - (size_t)m_buf) / sizeof(CharT);
    }   

public:
    size_t find(const string_base & str, size_t pos = npos) const noexcept
    {
        return find_internal(str.c_str(), str.length(), pos, case_sensitive);
    }

    size_t find(const CharT * s, size_t pos = npos) const noexcept
    {
        return find_internal(s, 0, pos, case_sensitive);
    }

    size_t find_i(const string_base & str, size_t pos = npos) const noexcept
    {
        return find_internal(str.c_str(), str.length(), pos, case_insensitive);
    }

    size_t find_i(const CharT * s, size_t pos = npos) const noexcept
    {
        return find_internal(s, 0, pos, case_insensitive);
    }

protected:
    BST_NOINLINE
    size_t find_internal(const CharT * s, size_t slen, size_t pos, char_case _case) const noexcept
    {
        if (is_buffer)
            return npos;

        slen = decode_data_len(s, slen, !is_buffer);
        if (slen == 0 || empty() || pos >= length())
            return npos;

        size_t res;
        if (_case == case_sensitive) {
            if (is_wstring)
                res = (size_t)StrStrW((LPCWSTR)m_buf + pos, (LPCWSTR)s);
            else
                res = (size_t)StrStrA((LPCSTR)m_buf + pos, (LPCSTR)s);
        } else {
            if (is_wstring)
                res = (size_t)StrStrIW((LPCWSTR)m_buf + pos, (LPCWSTR)s);
            else
                res = (size_t)StrStrIA((LPCSTR)m_buf + pos, (LPCSTR)s);
        }
        return (!res) ? npos : (res - (size_t)m_buf) / sizeof(CharT);
    }   

public:
    size_t find(const CharT c, size_t pos = 0) const noexcept
    {
        return find_internal(c, pos, case_sensitive);
    }

    size_t find_i(const CharT c, size_t pos = 0) const noexcept
    {
        return find_internal(c, pos, case_insensitive);
    }

protected:
    BST_NOINLINE
    size_t find_internal(const CharT c, size_t pos, char_case _case) const noexcept
    {
        if (is_buffer)
            return npos;

        if (empty() || pos >= length())
            return npos;

        size_t res;
        if (_case == case_sensitive) {
            if (is_wstring)
                res = (size_t)StrChrW((LPCWSTR)m_buf + pos, (WCHAR)c);
            else
                res = (size_t)StrChrA((LPCSTR)m_buf + pos, (CHAR)c);
        } else {
            if (is_wstring)
                res = (size_t)StrChrIW((LPCWSTR)m_buf + pos, (WCHAR)c);
            else
                res = (size_t)StrChrIA((LPCSTR)m_buf + pos, (CHAR)c);
        }  
        return (!res) ? npos : (res - (size_t)m_buf) / sizeof(CharT);
    }

public:
    size_t insert(size_t pos, const CharT * s, size_t n = 0) noexcept(NT)
    {
        return insert_internal(pos, s, n);
    }

    size_t insert(size_t pos, const string_base & str) noexcept(NT)
    {
        return insert_internal(pos, str.c_str, str.length());
    }

protected:
    BST_NOINLINE
    size_t insert_internal(size_t pos, const CharT * s, size_t slen) noexcept(NT)
    {
        slen = decode_data_len(s, slen, !is_buffer);
        if (slen == 0)
            return m_len;

        if (pos > length()) {
            BST_THROW_IF(!NT, C, 101, "Bad string pos");
            return npos;
        }
        size_t len = request_length(m_len + slen);
        if (len == npos)
            return npos;

        if (!empty())
            memmove(m_buf + pos + slen, m_buf + pos, m_len - pos + 1);

        memcpy(m_buf + pos, s, slen);
        if (!is_buffer)
            m_buf[len] = 0;

        pos += slen;
        m_len = len;
        return pos;
    }

public:
    bool assign_fmt(const CharT * fmt, ...) noexcept(NT)
    {
        va_list argptr;
        va_start(argptr, fmt);
        bool res = assign_fmt_internal(fmt, argptr, 0);
        va_end(argptr);
        return res;
    }

    bool assign(const fmt_string<CharT> fmt, ...) noexcept(NT)
    {
        va_list argptr;
        va_start(argptr, fmt);
        bool res = assign_fmt_internal(fmt.c_str(), argptr, 0);
        va_end(argptr);
        return res;
    }

    string_base & append(const fmt_string<CharT> fmt, ...) noexcept(NT)
    {
        va_list argptr;
        va_start(argptr, fmt);
        bool res = append_fmt_internal(fmt.c_str(), argptr);
        va_end(argptr);
        return *this;
    }

    string_base & append_fmt(const CharT * fmt, ...) noexcept(NT)
    {
        va_list argptr;
        va_start(argptr, fmt);
        bool res = append_fmt_internal(fmt, argptr);
        va_end(argptr);
        return *this;
    }

public:
    bool assign(int cp, const wchar_t * s, size_t len = 0) noexcept(NT)
    {
        return assign_wide_internal(cp, s, len);
    }

    bool assign(int cp, const char * s, size_t len = 0) noexcept(NT)
    {
        return assign_ansi_internal(cp, s, len);
    }

    string_base & append(int cp, const wchar_t * s, size_t len = 0) noexcept(NT)
    {
        append_wide_internal(cp, s, len);
        return *this;
    }

    string_base & append(int cp, const char * s, size_t len = 0) noexcept(NT)
    {
        append_ansi_internal(cp, s, len);
        return *this;
    }

protected:
    BST_NOINLINE
    bool assign_wide_internal(int cp, const wchar_t * s, size_t len = 0) noexcept(NT)
    {
        if (!s) {
            destroy();
            return true;
        }
        clear();
        return append_wide_internal(cp, s, len, 0);
    }

    BST_NOINLINE
    bool assign_ansi_internal(int cp, const char * s, size_t len = 0) noexcept(NT)
    {
        if (!s) {
            destroy();
            return true;
        }
        clear();
        return append_ansi_internal(cp, s, len, 0);
    }

    BST_NOINLINE
    bool append_wide_internal(int cp, const wchar_t * s, size_t slen = 0, size_t suffix = 64) noexcept(NT)
    {
        if (!is_string)
            return false;

        if (!s)
            return true;

        if ((SSIZE_T)slen <= 0)
            slen = ::wcslen(s);

        if (slen == 0)
            return true;

        SSIZE_T sz = WideCharToMultiByte(cp, 0, s, slen, nullptr, 0, nullptr, nullptr);
        if (sz <= 0) {
            m_last_error = e_convert;
            BST_THROW_IF(!NT, C, 301, "Unicode convert error");
            return false;
        }        
        size_t len = request_length(m_len + sz, suffix);
        if (len == npos)
            return false;

        sz = WideCharToMultiByte(cp, 0, s, slen, (LPSTR)m_buf + m_len, (int)sz, nullptr, nullptr);
        if (sz <= 0) {
            m_last_error = e_convert;
            BST_THROW_IF(!NT, C, 302, "Unicode convert error");
            return false;
        }
        m_len += sz;
        m_buf[m_len] = 0;
        return true;
    }

    BST_NOINLINE
    bool append_ansi_internal(int cp, const char * s, size_t slen = 0, size_t suffix = 64) noexcept(NT)
    {
        if (!is_wstring)
            return false;

        if (!s)
            return true;

        if ((SSIZE_T)slen <= 0)
            slen = ::strlen(s);

        if (slen == 0)
            return true;

        SSIZE_T sz = MultiByteToWideChar(cp, 0, s, slen, nullptr, 0);
        if (sz <= 0) {
            m_last_error = e_convert;
            BST_THROW_IF(!NT, C, 311, "Unicode convert error");
            return false;
        }        
        size_t len = request_length(m_len + sz, suffix);
        if (len == npos)
            return false;

        sz = MultiByteToWideChar(cp, 0, s, slen, (LPWSTR)m_buf + m_len, sz);
        if (sz <= 0) {
            m_last_error = e_convert;
            BST_THROW_IF(!NT, C, 312, "Unicode convert error");
            return false;
        }
        m_len += sz;
        m_buf[m_len] = 0;
        return true;
    }

public:
    int atoi(bool hex = false, size_t pos = 0) noexcept(NT)
    {
        INT64 res = atoi64_internal(false, 0, pos, hex);
        if (res < INT_MIN || res > INT_MAX) {
            m_last_error = e_convert;
            BST_THROW_IF(!NT, C, 301, "Incorrect string for converting");
        }
        return (int)res;
    }

    int atoi(int defvalue, size_t pos = 0, bool hex = false) noexcept
    {
        INT64 res = atoi64_internal(true, defvalue, pos, hex);
        if (res < INT_MIN || res > INT_MAX) {
            return defvalue;
        }
        return (int)res;
    }

    INT64 atoi64(bool hex = false, size_t pos = 0) noexcept(NT)
    {
        return atoi64_internal(false, 0, pos, hex);
    }

    INT64 atoi64(INT64 defvalue, size_t pos = 0, bool hex = false) noexcept
    {
        return atoi64_internal(true, defvalue, pos, hex);
    }

protected:
    INT64 atoi64_internal(bool dv, INT64 defvalue, size_t pos, bool hex) noexcept(NT)
    {
        INT64 res;
        BOOL x;
        if (is_wstring)
            x = StrToInt64ExW((LPCWSTR)m_buf + pos, STIF_DEFAULT, &res);
        else
            x = StrToInt64ExA((LPCSTR)m_buf + pos, STIF_DEFAULT, &res);
        if (!x) {
            if (!dv) {
                m_last_error = e_convert;
                BST_THROW_IF(!NT, C, 330, "Incorrect string for converting");
                return 0;
            }
            return defvalue;
        }
        return res;
    }

};


template <size_t PreAllocLen, typename CharT, bool NT = false>
class static_string : public string_base<CharT, NT>
{
protected:
    CharT m_content[PreAllocLen + 2];

    BST_INLINE
    void set_defaults() noexcept
    {
        m_buf = m_content;
        m_len = 0;
        m_capacity = PreAllocLen;
        m_is_static = true;
        m_last_error = non_error;
        m_content[0] = 0;
        m_content[PreAllocLen] = 0;
        m_content[PreAllocLen + 1] = 0;
    }

public:    
    enum { max_len = PreAllocLen };

    static_string()
    {
        set_defaults();
    }

    static_string(const CharT * s, size_t len = 0) noexcept(NT)
    {
        set_defaults();
        assign(s, len);
    }

    static_string(const string_base & str) noexcept(NT)
    {
        set_defaults();
        assign(str.c_str(), str.length());
    }

    static_string(const fmt_string<CharT> fmt, ...) noexcept(NT)
    {        
        set_defaults();
        va_list argptr;
        va_start(argptr, fmt);
        assign_fmt_internal(fmt.c_str(), argptr);
        va_end(argptr);
    }

    ~static_string() noexcept = default;

    /* copy-constructor */
    static_string(const static_string & str) noexcept(NT)
    {
        set_defaults();
        assign(str.c_data(), str.length());
    }

    /* move-constructor */
    static_string(static_string && str) noexcept
    {
        m_buf = m_content;
        m_len = str.m_len;
        m_capacity = str.m_capacity;
        m_is_static = true;
        m_last_error = str.m_last_error;
        memcpy(m_content, str.m_content, sizeof(m_content));
    }

    bool is_null() const
    {
        return false;
    }

    static_string & operator = (const static_string & str) noexcept(NT)
    {
        assign(str);
        return *this;
    }

    static_string & operator = (const CharT * s) noexcept(NT)
    {
        assign(s);
        return *this;
    }

    static_string & operator += (const static_string & str) noexcept(NT)
    {
        append(str);
        return *this;
    }

    static_string & operator += (const CharT * s) noexcept(NT)
    {
        append(s);
        return *this;
    }
};


template <typename CharT, bool NT = false>
class const_string : public string_base<CharT, NT>
{
public:
    const_string() noexcept = delete;

    ~const_string() noexcept = default;

    const_string(const CharT * s) noexcept
    {
        clone(s);
    }

    const_string(const const_string & str) noexcept
    {
        clone(str.c_str(), str.length());
    }

    const_string(const_string && str) noexcept
    {
        clone(str.c_str(), str.length());
    }

    const_string(const string_base & str) noexcept
    {
        clone(str.c_str(), str.length());
    }

    const_string & operator = (const const_string &) noexcept = delete;
    const_string & operator = (const_string &&) noexcept = delete;

    CharT * data() noexcept = delete;

protected:
    void clone(const CharT * s, size_t slen = 0) noexcept
    {
        m_buf = (CharT *)s;
        m_len = !m_buf ? 0 : (slen ? slen : get_length(s));
        m_capacity = m_len;
        m_is_static = true;    /* for disable free m_buf */
        m_last_error = non_error;
    }
};


} /* namespace detail */


template <typename CharT>
using string = detail::string_base<CharT>;

typedef detail::string_base<char>      str;
typedef detail::string_base<wchar_t>   wstr;
typedef detail::string_base<UCHAR>     buf;

typedef const detail::const_string<char>     c_str;
typedef const detail::const_string<wchar_t>  c_wstr;
typedef const detail::const_string<UCHAR>    c_buf;

template <size_t PreAllocLen, typename CharT>
using static_string = detail::static_string<PreAllocLen, CharT>;

template <size_t PreAllocLen>
using static_wstr = detail::static_string<PreAllocLen, wchar_t>;

typedef detail::static_string<BST_MAX_PATH_LEN, wchar_t>  filepath;
typedef detail::static_string<BST_MAX_NAME_LEN, wchar_t>  filename;

typedef detail::static_string<BST_MAX_PATH_LEN, wchar_t>  wsfp;  /* static string (file path) */
typedef detail::static_string<BST_MAX_NAME_LEN, wchar_t>  wsfn;  /* static string (file name) */

template <size_t PreAllocLen>
using static_str = detail::static_string<PreAllocLen, char>;

typedef detail::static_string<BST_MAX_PATH_LEN, char>   filepath_a;
typedef detail::static_string<BST_MAX_NAME_LEN, char>   filename_a;

typedef detail::static_string<BST_MAX_PATH_LEN, char>   sfp;  /* static string (file path) */
typedef detail::static_string<BST_MAX_NAME_LEN, char>   sfn;  /* static string (file name) */

template <size_t PreAllocLen>
using static_buf = detail::static_string<PreAllocLen, UCHAR>;


namespace nt {   /* nothrow */

    const bool kNoThrow = true;

    template <typename CharT>
    using string = detail::string_base<CharT, kNoThrow>;

    typedef detail::string_base<char,    kNoThrow>   str;
    typedef detail::string_base<wchar_t, kNoThrow>   wstr;
    typedef detail::string_base<UCHAR,   kNoThrow>   buf;

    template <size_t PreAllocLen, typename CharT>
    using static_string = detail::static_string<PreAllocLen, CharT>;

    template <size_t PreAllocLen>
    using static_wstr = detail::static_string<PreAllocLen, wchar_t>;

    typedef detail::static_string<BST_MAX_PATH_LEN, wchar_t, kNoThrow>  filepath;
    typedef detail::static_string<BST_MAX_NAME_LEN, wchar_t, kNoThrow>  filename;

    template <size_t PreAllocLen>
    using static_str = detail::static_string<PreAllocLen, char>;

    typedef detail::static_string<BST_MAX_PATH_LEN, char, kNoThrow>   filepath_a;
    typedef detail::static_string<BST_MAX_NAME_LEN, char, kNoThrow>   filename_a;

    template <size_t PreAllocLen>
    using static_buf = detail::static_string<PreAllocLen, UCHAR>;

} /* namespace nt */

} /* namespace bst */

