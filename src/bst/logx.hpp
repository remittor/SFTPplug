#pragma once

#include <windows.h>

namespace bst {

#define BST_LL_FATAL_ERROR 1
#define BST_LL_CRIT_ERROR  2
#define BST_LL_ERROR       3
#define BST_LL_WARNING     4
#define BST_LL_NOTICE      5
#define BST_LL_INFO        6
#define BST_LL_DEBUG       7
#define BST_LL_TRACE       8 

#define BST_LL_STRING   "#FCEwnidt"

namespace log {

void SetLogLevel(int level) noexcept;
void PrintMsgA(int level, const char * fmt, ...) noexcept;
void PrintMsgW(int level, const wchar_t * fmt, ...) noexcept;

} /* namespace log */

} /* namespace bst */

#define LOGX_IF(_level_, _cond_, ...)   if ((_cond_)) ::bst::log::PrintMsgA(_level_, __VA_ARGS__)
#define LOGX(_level_, ...)              ::bst::log::PrintMsgA(_level_, __VA_ARGS__)

#define WLOGX_IF(_level_, _cond_, ...)  if ((_cond_)) ::bst::log::PrintMsgW(_level_, __VA_ARGS__)
#define WLOGX(_level_, ...)             ::bst::log::PrintMsgW(_level_, __VA_ARGS__)

