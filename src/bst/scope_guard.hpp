/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 * Licensed under the Apache License Version 2.0
 * Original name: folly ScopeGuard
 */

#pragma once

#include "bst.hpp"
#include <type_traits>

namespace bst {

namespace detail {

class ScopeGuardBase
{
public:
    void dismiss() noexcept
    {
        m_dismissed = true;
    }

protected:
    ScopeGuardBase() noexcept 
      : m_dismissed(false)
    {
        //
    }

    static void warnAboutToCrash() noexcept
    {
        OutputDebugStringA("This program will now terminate because a bst::ScopeGuard callback threw an exception.\n");
    }

    static ScopeGuardBase makeEmptyScopeGuard() noexcept
    {
        return ScopeGuardBase{};
    }

    template <typename T>
    static const T & asConst(const T & t) noexcept
    {
        return t;
    }

    bool m_dismissed;
};

template <typename FuncType, bool InvokeNoexcept>
class ScopeGuard : public ScopeGuardBase
{
public:
    explicit ScopeGuard(FuncType& fn) noexcept(std::is_nothrow_copy_constructible<FuncType>::value)
      : ScopeGuard(asConst(fn), makeFailsafe(std::is_nothrow_copy_constructible<FuncType>{}, &fn))
    {
        //
    }

    explicit ScopeGuard(const FuncType& fn) noexcept(std::is_nothrow_copy_constructible<FuncType>::value)
      : ScopeGuard(fn, makeFailsafe(std::is_nothrow_copy_constructible<FuncType>{}, &fn))
    {
        //
    }

    explicit ScopeGuard(FuncType&& fn) noexcept(std::is_nothrow_move_constructible<FuncType>::value)
      : ScopeGuard(std::move_if_noexcept(fn), makeFailsafe(std::is_nothrow_move_constructible<FuncType>{}, &fn))
    {
        //
    }

    ScopeGuard(ScopeGuard&& other) noexcept(std::is_nothrow_move_constructible<FuncType>::value)
      : m_function(std::move_if_noexcept(other.m_function))
    {
        // If the above line attempts a copy and the copy throws, other is
        // left owning the cleanup action and will execute it (or not) depending
        // on the value of other.dismissed_. The following lines only execute
        // if the move/copy succeeded, in which case *this assumes ownership of
        // the cleanup action and dismisses other.
        m_dismissed = std::exchange(other.m_dismissed, true);
    }

    ~ScopeGuard() noexcept(InvokeNoexcept)
    {
        if (!m_dismissed) {
            execute();
        }
    }

private:
    static ScopeGuardBase makeFailsafe(std::true_type, const void*) noexcept
    {
        return makeEmptyScopeGuard();
    }

    template <typename Fn>
    static auto makeFailsafe(std::false_type, Fn* fn) noexcept
     -> ScopeGuard<decltype(std::ref(*fn)), InvokeNoexcept>
    {
        return ScopeGuard<decltype(std::ref(*fn)), InvokeNoexcept> { std::ref(*fn) };
    }

    template <typename Fn>
    explicit ScopeGuard(Fn&& fn, ScopeGuardBase&& failsafe)
      : ScopeGuardBase{}
      , m_function(std::forward<Fn>(fn))
    {
        failsafe.dismiss();
    }

    void* operator new(std::size_t) = delete;

    void execute() noexcept(InvokeNoexcept)
    {
        if (InvokeNoexcept) {
            try {
                m_function();
            }
            catch (...) {
                warnAboutToCrash();
                std::terminate();
            }
        } else {
            m_function();
        }
    }

    FuncType m_function;
};

template <typename F, bool INE>
using ScopeGuardDecay = ScopeGuard<typename std::decay<F>::type, INE>;

} /* namespace detail */


/**
 * ScopeGuard is a general implementation of the "Initialization is
 * Resource Acquisition" idiom.  Basically, it guarantees that a function
 * is executed upon leaving the current scope unless otherwise told.
 *
 * The makeGuard() function is used to create a new ScopeGuard object.
 * It can be instantiated with a lambda function, a std::function<void()>,
 * a functor, or a void(*)() function pointer.
 *
 *
 * Usage example: Add a friend to memory if and only if it is also added
 * to the db.
 *
 * void User::addFriend(User& newFriend) {
 *   // add the friend to memory
 *   friends_.push_back(&newFriend);
 *
 *   // If the db insertion that follows fails, we should
 *   // remove it from memory.
 *   auto guard = makeGuard([&] { friends_.pop_back(); });
 *
 *   // this will throw an exception upon error, which
 *   // makes the ScopeGuard execute UserCont::pop_back()
 *   // once the Guard's destructor is called.
 *   db_->addFriend(GetName(), newFriend.GetName());
 *
 *   // an exception was not thrown, so don't execute
 *   // the Guard.
 *   guard.dismiss();
 * }
 *
 * Stolen from:
 *   Andrei's and Petru Marginean's CUJ article:
 *     http://drdobbs.com/184403758
 *   and the loki library:
 *     http://loki-lib.sourceforge.net/index.php?n=Idioms.ScopeGuardPointer
 *   and triendl.kj article:
 *     http://www.codeproject.com/KB/cpp/scope_guard.aspx
 */
template <typename F>
_Check_return_ detail::ScopeGuardDecay<F, true> makeGuard(F&& f) noexcept(
    noexcept(detail::ScopeGuardDecay<F, true>(static_cast<F&&>(f))))
{
    return detail::ScopeGuardDecay<F, true>(static_cast<F&&>(f));
}


namespace detail {

/**
 * ScopeGuard used for executing a function when leaving the current scope
 * depending on the presence of a new uncaught exception.
 *
 * If the executeOnException template parameter is true, the function is
 * executed if a new uncaught exception is present at the end of the scope.
 * If the parameter is false, then the function is executed if no new uncaught
 * exceptions are present at the end of the scope.
 *
 * Used to implement SCOPE_FAIL and SCOPE_SUCCESS below.
 */
template <typename FuncType, bool ExecuteOnException>
class ScopeGuardEx
{
public:
    explicit ScopeGuardEx(const FuncType& fn)
      : m_guard(fn)
    {
        //
    }

    explicit ScopeGuardEx(FuncType&& fn)
      : m_guard(std::move(fn))
    {
        //
    }

    ScopeGuardEx(ScopeGuardEx&& other) = default;

    ~ScopeGuardEx() noexcept(ExecuteOnException)
    {
        if (ExecuteOnException != (m_exceptionCounter < std::uncaught_exceptions()))
        {
            m_guard.dismiss();
        }
    }

private:
    void* operator new(std::size_t) = delete;
    void operator delete(void*) = delete;

    ScopeGuard<FuncType, ExecuteOnException> m_guard;
    int m_exceptionCounter{ std::uncaught_exceptions() };
};

} /* namespace detail */


enum class ScopeGuardOnFailure {};

template <typename FuncType>
detail::ScopeGuardEx<typename std::decay<FuncType>::type, true>
operator + (ScopeGuardOnFailure, FuncType&& fn)
{
    return detail::ScopeGuardEx< typename std::decay<FuncType>::type, true> ( std::forward<FuncType>(fn) );
}


enum class ScopeGuardOnSuccess {};

template <typename FuncType>
detail::ScopeGuardEx<typename std::decay<FuncType>::type, false>
operator + (ScopeGuardOnSuccess, FuncType&& fn)
{
    return detail::ScopeGuardEx< typename std::decay<FuncType>::type, false> ( std::forward<FuncType>(fn) );
}


enum class ScopeGuardOnExit {};

template <typename FuncType>
detail::ScopeGuard<typename std::decay<FuncType>::type, true>
operator + (ScopeGuardOnExit, FuncType&& fn)
{
    return detail::ScopeGuard< typename std::decay<FuncType>::type, true>( std::forward<FuncType>(fn) );
}


} /* namespace bst */


#define SCOPE_EXIT \
    auto BST_GENSYM(SCOPE_EXIT_STATE) = ::bst::ScopeGuardOnExit() + [&]() noexcept

#define SCOPE_FAILURE \
    auto BST_GENSYM(SCOPE_FAILURE_STATE) = ::bst::ScopeGuardOnFailure() + [&]() noexcept

#define SCOPE_SUCCESS \
    auto BST_GENSYM(SCOPE_SUCCESS_STATE) = ::bst::ScopeGuardOnSuccess() + [&]()

