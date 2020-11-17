#pragma once

#include "bst.hpp"
#include "srw_lock.hpp"

namespace bst {

template <typename T>
class list;

template <typename T>
class list_enum;


template <typename T>
class list_node
{
protected:
    friend class list<T>;
    friend class list_enum<T>;

    list_node * m_prev;
    list_node * m_next;
    T * m_obj;

public:
    list_node() noexcept 
      : m_obj(nullptr)  // head node
    {
        m_prev = m_next = this;
    }

    list_node(list_node * prev, list_node * next, T * obj) noexcept
      : m_prev(prev)
      , m_next(next)
      , m_obj(obj)
    {
        m_prev->m_next = m_next->m_prev = this;
    }

    ~list_node() noexcept
    {
        m_prev->m_next = m_next;
        m_next->m_prev = m_prev;
        if (m_obj)
            delete m_obj;
    }
};


template <typename T>
class list
{
protected:
    friend class list_enum<T>;

    list_node<T> m_base;
    srw_lock     m_mutex;
    size_t       m_size;

public:
    list() noexcept
      : m_base()
    {
        m_size = 0;
    }

    ~list() noexcept
    { 
        clear();
    }

    void clear() noexcept
    {
        scoped_write_lock lock(m_mutex);
        while (!is_empty_internal()) {
            delete m_base.m_next;
        }
        m_size = 0;
    }

    srw_lock & get_mutex()
    {
        return m_mutex;
    }

    size_t size() const noexcept
    {
        return m_size;
    }

    bool empty() const
    {
        return m_size == 0;
    }

    bool find(T * obj) const noexcept
    {
        scoped_read_lock lock(m_mutex);
        return find_node(obj) ? true : false;
    }

    bool add(T * obj)
    {
        if (obj) {
            scoped_write_lock lock(m_mutex);
            return add_internal(obj);
        }
        return false;
    }

    bool add(T * obj, const std::nothrow_t &) noexcept
    {
        if (obj) {
            scoped_write_lock lock(m_mutex);
            return add_internal(obj, std::nothrow);
        }
        return false;
    }

    bool del(T * obj) noexcept
    {
        if (obj) {
            scoped_write_lock write_lock(m_mutex);
            return pop_internal(obj, true);
        }
        return false;
    }

    bool pop(T * obj) noexcept
    {
        if (obj) {      
            scoped_write_lock write_lock(m_mutex);
            return pop_internal(obj, false);
        }
        return false;
    }

protected:
    bool is_empty_internal() noexcept
    {
        return (m_base.m_next == &m_base) && (m_base.m_prev == &m_base);
    }

    list_node<T> * find_node(T * obj) noexcept
    {
        if (obj && !empty())
            for (list_node<T> * node = m_base.m_next; node != &m_base; node = node->m_next)
                if (node->m_obj == obj)
                    return node;
        return nullptr;
    }

    bool add_internal(T * obj)
    {
        if (!find_node(obj)) {
            list_node<T> * node = new(std::nothrow) list_node<T>(m_base.m_prev, &m_base, obj);
            BST_THROW_IF(!node, F, 1, "Bad list entry alloc");
            if (node) {
                m_size++;
                return true;
            }
        }
        return false;
    }

    bool add_internal(T * obj, const std::nothrow_t &) noexcept
    {
        if (!find_node(obj)) {
            list_node<T> * node = new(std::nothrow) list_node<T>(m_base.m_prev, &m_base, obj);
            if (node) {
                m_size++;
                return true;
            }
        }
        return false;
    }

    bool pop_internal(T * obj, bool free_obj) noexcept
    {
        list_node<T> * node = find_node(obj);
        if (node) {
            if (!free_obj)
                node->m_obj = nullptr;
            delete node;
            m_size--;
            return true;
        }
        return false;
    }
};



template <typename T>
class list_enum : private noncopyable
{
private:
    list<T>      * m_list;
    list_node<T> * m_node;
    bool           m_write_lock;

public:
    list_enum() = delete;

    list_enum(list<T> & list, const bst::read_lock_t &) noexcept
      : m_list(&list)
    {
        m_write_lock = false;
        m_list->m_mutex.read_lock();
        reset();
    }

    list_enum(list<T> & list, const bst::write_lock_t &) noexcept
      : m_list(&list)
    {
        m_write_lock = true;
        m_list->m_mutex.write_lock();
        reset();
    }

    ~list_enum() noexcept
    {
        m_list->m_mutex.unlock();
    }

    list_node<T> * begin() noexcept
    {
        return &(m_list->m_base);
    }

    void reset() noexcept
    {
        m_node = begin();
    }

    T * get_next() noexcept
    {
        m_node = m_node->m_next;
        return (m_node == begin()) ? nullptr : m_node->m_obj;
    }

    bool find(T * obj) noexcept
    {
        return m_list->find_node(obj) ? true : false;
    }

    bool add(T * obj)
    {
        BST_THROW_IF(!m_write_lock, F, 1, "Bad use of list"); 
        return m_list->add_internal(obj);
    }

    bool try_add(T * obj) noexcept
    {
        if (!m_write_lock)
            return false;

        return m_list->add_internal(obj, std::nothrow);
    }

    bool add(T * obj, const std::nothrow_t &) noexcept
    {
        return try_add(obj);
    }

    bool del(T * obj) noexcept
    {
        if (!m_write_lock)
            return false;

        return m_list->pop_internal(obj, true);
    }

    bool pop(T * obj) noexcept
    {
        if (!m_write_lock)
            return false;

        return m_list->pop_internal(obj, false);
    }

    T & operator * ()
    {
        return m_node->m_obj;
    }

    list_enum & operator ++ ()
    {
        m_node = m_node->m_next;
        return *this;
    }

    list_enum & operator -- ()
    {
        m_node = m_node->m_prev;
        return *this;
    }

    bool operator == (const list_enum & other)
    {
        return m_node == other.m_node;
    }

    bool operator != (const list_enum & other)
    {
        return m_node != other.m_node;
    }
};


} /* namespace bst */

