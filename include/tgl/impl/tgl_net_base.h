/*
    This file is part of tgl-library

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

    Copyright Topology LP 2016-2017
*/

#pragma once

#include <tgl/tgl_online_status_observer.h>
#include <tgl/tgl_mtproto_client.h>
#include <tgl/tgl_net.h>
#include <tgl/tgl_timer.h>

#include <chrono>
#include <deque>
#include <memory>
#include <cstring>
#include <vector>

// This is a default base implementation of tgl_connection. It should include the public headers only.

class tgl_net_buffer {
public:
    explicit tgl_net_buffer(size_t size)
        : m_data(size)
        , m_current_position(0)
    { }

    tgl_net_buffer(const char* data, size_t size)
        : m_data(size)
        , m_current_position(0)
    {
        std::memcpy(m_data.data(), data, size);
    }

    char* data()
    {
        assert(m_data.size() >= m_current_position);
        return m_data.data() + m_current_position;
    }

    size_t size() const
    {
        assert(m_data.size() >= m_current_position);
        return m_data.size() - m_current_position;
    }

    void advance(size_t diff)
    {
        m_current_position += diff;
        assert(m_data.size() >= m_current_position);
    }

    bool empty() const { return size() == 0; }

    std::vector<char>& raw_buffer() { return m_data; }

private:
    std::vector<char> m_data;
    size_t m_current_position;
};

class tgl_connection_base : public std::enable_shared_from_this<tgl_connection_base>
        , public tgl_connection, public tgl_online_status_observer
{
public:
    tgl_connection_base(
            const std::vector<std::pair<std::string, int>>& ipv4_options,
            const std::vector<std::pair<std::string, int>>& ipv6_options,
            const std::weak_ptr<tgl_mtproto_client>& client);
    virtual ~tgl_connection_base();

    virtual void open() override;
    virtual void close() override;
    virtual ssize_t read(void* buffer, size_t len) override;
    virtual ssize_t write(const void* data, size_t len) override;
    virtual ssize_t peek(void* data, size_t len) override;
    virtual size_t available_bytes_for_read() override { return m_available_bytes_for_read; }
    virtual void flush() override;
    virtual tgl_connection_status status() const override { return m_connection_status; }

    virtual void on_online_status_changed(tgl_online_status status) override;
    bool is_online() const { return m_online_status == tgl_online_status::wwan_online || m_online_status == tgl_online_status::non_wwan_online; }

protected:
    virtual bool connect() = 0;
    virtual void disconnect() = 0;
    virtual void start_read() = 0;
    virtual void start_write() = 0;

    bool is_connecting() const { return m_state == connection_state::connecting; }
    bool ipv6_enabled() const;
    void try_read();
    void try_write();

    void connect_finished(bool success);
    void data_received(const std::shared_ptr<tgl_net_buffer>& buffer);
    void lost();
    void error();

    void bytes_sent(size_t bytes);

    std::string m_ipv4_address;
    std::string m_ipv6_address;
    int m_ipv4_port;
    int m_ipv6_port;
    std::deque<std::shared_ptr<tgl_net_buffer>> m_write_buffer_queue;

private:
    enum class connection_state {
        none,
        connecting,
        ready,
        failed,
        closed,
    };

    void bytes_received(size_t bytes);
    void consume_data();
    void schedule_restart();
    void restart();

    void start_ping_timer();
    void stop_ping_timer();
    void ping();

    void clear_buffers();
    void set_state(connection_state state);

    connection_state m_state;

    std::shared_ptr<tgl_timer_factory> m_timer_factory;

    std::shared_ptr<tgl_timer> m_ping_timer;
    std::chrono::time_point<std::chrono::steady_clock> m_last_receive_time;

    std::shared_ptr<tgl_timer> m_restart_timer;
    std::chrono::time_point<std::chrono::steady_clock> m_last_restart_time;
    std::chrono::milliseconds m_restart_duration;

    std::deque<std::shared_ptr<tgl_net_buffer>> m_read_buffer_queue;
    size_t m_available_bytes_for_read;
    std::weak_ptr<tgl_mtproto_client> m_mtproto_client;
    std::weak_ptr<tgl_online_status_observer> m_this_weak_observer;

    tgl_online_status m_online_status;
    tgl_connection_status m_connection_status;
};
