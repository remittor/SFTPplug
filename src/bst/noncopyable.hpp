#pragma once

#include "core.hpp"

namespace bst {

namespace detail {

class noncopyable
{
protected:
    constexpr noncopyable() = default;
    ~noncopyable() = default;
private:
    noncopyable( const noncopyable& ) = delete;
    noncopyable& operator =( const noncopyable& ) = delete;
};

class nonmovable
{
protected:
    nonmovable() = default;
private:
    nonmovable( nonmovable && ) = delete;
    nonmovable &operator =( nonmovable && ) = delete;
};

class NonCopyableNonMoveable
{
public:
    NonCopyableNonMoveable() = default;
private:
    NonCopyableNonMoveable( const NonCopyableNonMoveable& ) = delete;
    NonCopyableNonMoveable( NonCopyableNonMoveable&& ) = delete;
    NonCopyableNonMoveable& operator =( const NonCopyableNonMoveable& ) = delete;
    NonCopyableNonMoveable& operator =( NonCopyableNonMoveable&& ) = delete;
};

} /* namespace detail */

typedef detail::noncopyable noncopyable;
typedef detail::noncopyable NonCopyable;

typedef detail::nonmovable  nonmovable;
typedef detail::nonmovable  NonMovable;

typedef detail::NonCopyableNonMoveable NonCopyableNonMoveable;

} /* namespace bst */
