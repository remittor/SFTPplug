#include "logx.hpp"
#include <stdio.h>
#include <vadefs.h>

namespace bst {

namespace log {

static int  g_log_level = BST_LL_TRACE;

static const char g_log_level_str[] = BST_LL_STRING "--------------------------";

void SetLogLevel(int level) noexcept
{
    if (level < 0) {
        g_log_level = -1;
    }
    else if (level > BST_LL_TRACE) {
        g_log_level = BST_LL_TRACE;
    }
    else {
        g_log_level = level;
    }
}

void PrintMsgA(int level, const char * fmt, ...) noexcept
{
    char buf[4096];
    if (level <= g_log_level && level > 0) {
        va_list argptr;
        va_start(argptr, fmt);
        const size_t prefix_len = 9;
        memcpy(buf, "[SFTP-X]", prefix_len - 1);
        buf[prefix_len - 3] = g_log_level_str[level];
        buf[prefix_len - 1] = 0x20;
        int len = _vsnprintf(buf + prefix_len, _countof(buf)-2, fmt, argptr);
        va_end(argptr);
        if (len < 0) {
            strcat(buf, "<INCORRECT-INPUT-DATA> ");
            strcat(buf, fmt);
        } else {
            len += prefix_len;
            buf[len] = 0;
        }
        OutputDebugStringA(buf);
    }
}

void PrintMsgW(int level, const wchar_t * fmt, ...) noexcept
{
    union {
        struct {
            wchar_t reserved[4];
            wchar_t wbuf[4096];
        };
        char buf[4096 * 2];
    };
    if (level <= g_log_level && level > 0) {
        va_list argptr;
        va_start(argptr, fmt);
        const size_t prefix_len = 9;
        memcpy(wbuf, L"[SFTP-X]", (prefix_len - 1) * sizeof(wchar_t));
        wbuf[prefix_len - 3] = (wchar_t)g_log_level_str[level];
        wbuf[prefix_len - 1] = 0x20;
        int len = _vsnwprintf(wbuf + prefix_len, _countof(wbuf)-2, fmt, argptr);
        va_end(argptr);
        if (len < 0) {
            wcscat(wbuf, L"<INCORRECT-INPUT-DATA> ");
            wcscat(wbuf, fmt);
            len = (int)wcslen(wbuf);
        } else {
            len += prefix_len;
        }
        len = WideCharToMultiByte(CP_ACP, 0, wbuf, len, (LPSTR)buf, sizeof(buf)-2, NULL, NULL);
        buf[(len > 0) ? len : 0] = 0;
        OutputDebugStringA(buf);
    }
}

} /* namespace log */

} /* namespace bst */
