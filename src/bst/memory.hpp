#pragma once

#include <windows.h>
#include "core.hpp"

namespace bst {

BST_FORCEINLINE
void * malloc(size_t size) noexcept
{
    return ::malloc(size);
}

BST_FORCEINLINE
void * calloc(size_t elem_count, size_t elem_size) noexcept
{
    return ::calloc(elem_count, elem_size);
}

BST_FORCEINLINE
void * realloc(void * ptr, size_t newsize) noexcept
{
    return ::realloc(ptr, newsize);
}

BST_FORCEINLINE
void free(void * ptr) noexcept
{
    ::free(ptr);   // CRTLIB check value for NULL
}

#define BST_FREE(_ptr_) do { if (_ptr_) { bst::free(_ptr_); _ptr_ = nullptr; } } while(0)

} /* namespace bst */

