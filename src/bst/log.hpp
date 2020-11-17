#pragma once

#include "logx.hpp"


#if defined(BST_MAX_LOG_LEVEL) && BST_MAX_LOG_LEVEL >= BST_LL_TRACE
#define LOGt(...)                  LOGX(BST_LL_TRACE, __VA_ARGS__)
#define LOGt_IF(_cond_, ...)    LOGX_IF(BST_LL_TRACE, (_cond_), __VA_ARGS__)
#define WLOGt(...)                WLOGX(BST_LL_TRACE, __VA_ARGS__)
#define WLOGt_IF(_cond_, ...)  WLOGX_IF(BST_LL_TRACE, (_cond_), __VA_ARGS__)
#else
#define LOGt(...)  
#define LOGt_IF(_cond_, ...) 
#define WLOGt(...) 
#define WLOGt_IF(_cond_, ...)
#endif

#if defined(BST_MAX_LOG_LEVEL) && BST_MAX_LOG_LEVEL >= BST_LL_DEBUG
#define LOGd(...)                  LOGX(BST_LL_DEBUG, __VA_ARGS__)
#define LOGd_IF(_cond_, ...)    LOGX_IF(BST_LL_DEBUG, (_cond_), __VA_ARGS__)
#define WLOGd(...)                WLOGX(BST_LL_DEBUG, __VA_ARGS__)
#define WLOGd_IF(_cond_, ...)  WLOGX_IF(BST_LL_DEBUG, (_cond_), __VA_ARGS__)
#else
#define LOGd(...)  
#define LOGd_IF(_cond_, ...) 
#define WLOGd(...) 
#define WLOGd_IF(_cond_, ...)
#endif

#if defined(BST_MAX_LOG_LEVEL) && BST_MAX_LOG_LEVEL >= BST_LL_INFO
#define LOGi(...)                  LOGX(BST_LL_INFO, __VA_ARGS__)
#define LOGi_IF(_cond_, ...)    LOGX_IF(BST_LL_INFO, (_cond_), __VA_ARGS__)
#define WLOGi(...)                WLOGX(BST_LL_INFO, __VA_ARGS__)
#define WLOGi_IF(_cond_, ...)  WLOGX_IF(BST_LL_INFO, (_cond_), __VA_ARGS__)
#else
#define LOGi(...)  
#define LOGi_IF(_cond_, ...) 
#define WLOGi(...) 
#define WLOGi_IF(_cond_, ...)
#endif

#if defined(BST_MAX_LOG_LEVEL) && BST_MAX_LOG_LEVEL >= BST_LL_NOTICE
#define LOGn(...)                  LOGX(BST_LL_NOTICE, __VA_ARGS__)
#define LOGn_IF(_cond_, ...)    LOGX_IF(BST_LL_NOTICE, (_cond_), __VA_ARGS__)
#define WLOGn(...)                WLOGX(BST_LL_NOTICE, __VA_ARGS__)
#define WLOGn_IF(_cond_, ...)  WLOGX_IF(BST_LL_NOTICE, (_cond_), __VA_ARGS__)
#else
#define LOGn(...)  
#define LOGn_IF(_cond_, ...) 
#define WLOGn(...) 
#define WLOGn_IF(_cond_, ...)
#endif

#if defined(BST_MAX_LOG_LEVEL) && BST_MAX_LOG_LEVEL >= BST_LL_WARNING
#define LOGw(...)                  LOGX(BST_LL_WARNING, __VA_ARGS__)
#define LOGw_IF(_cond_, ...)    LOGX_IF(BST_LL_WARNING, (_cond_), __VA_ARGS__)
#define WLOGw(...)                WLOGX(BST_LL_WARNING, __VA_ARGS__)
#define WLOGw_IF(_cond_, ...)  WLOGX_IF(BST_LL_WARNING, (_cond_), __VA_ARGS__)
#else
#define LOGw(...)  
#define LOGw_IF(_cond_, ...) 
#define WLOGw(...) 
#define WLOGw_IF(_cond_, ...)
#endif

#if defined(BST_MAX_LOG_LEVEL) && BST_MAX_LOG_LEVEL >= BST_LL_ERROR
#define LOGe(...)                  LOGX(BST_LL_ERROR, __VA_ARGS__)
#define LOGe_IF(_cond_, ...)    LOGX_IF(BST_LL_ERROR, (_cond_), __VA_ARGS__)
#define WLOGe(...)                WLOGX(BST_LL_ERROR, __VA_ARGS__)
#define WLOGe_IF(_cond_, ...)  WLOGX_IF(BST_LL_ERROR, (_cond_), __VA_ARGS__)
#else
#define LOGe(...)  
#define LOGe_IF(_cond_, ...) 
#define WLOGe(...) 
#define WLOGe_IF(_cond_, ...)
#endif

#if defined(BST_MAX_LOG_LEVEL) && BST_MAX_LOG_LEVEL >= BST_LL_CRIT_ERROR
#define LOGc(...)                  LOGX(BST_LL_CRIT_ERROR, __VA_ARGS__)
#define LOGc_IF(_cond_, ...)    LOGX_IF(BST_LL_CRIT_ERROR, (_cond_), __VA_ARGS__)
#define WLOGc(...)                WLOGX(BST_LL_CRIT_ERROR, __VA_ARGS__)
#define WLOGc_IF(_cond_, ...)  WLOGX_IF(BST_LL_CRIT_ERROR, (_cond_), __VA_ARGS__)
#else
#define LOGc(...)  
#define LOGc_IF(_cond_, ...) 
#define WLOGc(...) 
#define WLOGc_IF(_cond_, ...)
#endif

#if defined(BST_MAX_LOG_LEVEL) && BST_MAX_LOG_LEVEL >= BST_LL_FATAL_ERROR
#define LOGf(...)                  LOGX(BST_LL_FATAL_ERROR, __VA_ARGS__)
#define LOGf_IF(_cond_, ...)    LOGX_IF(BST_LL_FATAL_ERROR, (_cond_), __VA_ARGS__)
#define WLOGf(...)                WLOGX(BST_LL_FATAL_ERROR, __VA_ARGS__)
#define WLOGf_IF(_cond_, ...)  WLOGX_IF(BST_LL_FATAL_ERROR, (_cond_), __VA_ARGS__)
#else
#define LOGf(...)  
#define LOGf_IF(_cond_, ...) 
#define WLOGf(...) 
#define WLOGf_IF(_cond_, ...)
#endif

