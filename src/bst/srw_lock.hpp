#pragma once

#include "bst.hpp"

namespace bst {

typedef struct _RTL_SRWLOCK {
    PVOID Ptr;
} RTL_SRWLOCK, *PRTL_SRWLOCK;


class srw_lock : private noncopyable
{
public:
    srw_lock() noexcept;
    ~srw_lock() noexcept;

    void lock_shared() noexcept;
    void unlock_shared() noexcept;

    void lock_exclusive() noexcept;
    void unlock_exclusive() noexcept;

    void unlock() noexcept;

    void read_lock() noexcept
    {
        lock_shared();
    }

    void read_unlock() noexcept
    {
        unlock_shared();
    }

    void write_lock() noexcept
    {
        lock_exclusive();
    }

    void write_unlock() noexcept
    {
        unlock_exclusive();
    }

private:
    RTL_SRWLOCK m_lock;
};

typedef srw_lock  srw_mutex;


struct read_lock_t { };
const read_lock_t read_lock = {};

struct write_lock_t { };
const write_lock_t write_lock = {};


class scoped_read_lock : private noncopyable
{
public:
    scoped_read_lock() = delete;

    explicit scoped_read_lock(srw_mutex & mutex) noexcept : m_mutex(mutex)
    {
        m_mutex.read_lock();
    }

    ~scoped_read_lock() noexcept
    {
        m_mutex.read_unlock();
    }

    void lock() noexcept
    {
        m_mutex.read_lock();
    }

    void unlock() noexcept
    {
        m_mutex.read_unlock();
    }

    srw_mutex & get_mutex() noexcept
    {
        return m_mutex;
    }

private:
    srw_mutex & m_mutex;
};


class scoped_write_lock : private noncopyable
{
public:
    scoped_write_lock() = delete;

    explicit scoped_write_lock(srw_mutex & mutex) noexcept : m_mutex(mutex)
    {
        m_mutex.write_lock();
    }

    ~scoped_write_lock() noexcept
    {
        m_mutex.write_unlock();
    }

    void lock() noexcept
    {
        m_mutex.write_lock();
    }

    void unlock() noexcept
    {
        m_mutex.write_unlock();
    }

    srw_mutex & get_mutex() noexcept
    {
        return m_mutex;
    }

private:
    srw_mutex & m_mutex;
};


} /* namespace */
