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

    Copyright Vitaly Valtman 2013-2015
    Copyright Topology LP 2016
*/

#ifndef __TGL_NET_ASIO_H__
#define __TGL_NET_ASIO_H__

#include "tgl-net.h"
#include "types/tgl_online_status_observer.h"

#include <boost/asio.hpp>
#include <chrono>
#include <deque>
#include <memory>

enum conn_state {
    conn_none,
    conn_connecting,
    conn_ready,
    conn_failed,
    conn_closed,
};

struct tgl_dc;
struct tgl_session;

class tgl_connection_asio : public std::enable_shared_from_this<tgl_connection_asio>
        , public tgl_connection, public tgl_online_status_observer
{
public:
    tgl_connection_asio(boost::asio::io_service& io_service,
            const std::string& host,
            int port,
            const std::weak_ptr<tgl_session>& session,
            const std::weak_ptr<tgl_dc>& dc,
            const std::shared_ptr<mtproto_client>& client);
    virtual ~tgl_connection_asio();

    virtual void open() override;
    virtual void close() override;
    virtual ssize_t read(void* buffer, size_t len) override;
    virtual ssize_t write(const void* data, size_t len) override;
    virtual void flush() override;
    virtual const std::weak_ptr<tgl_dc>& get_dc() const override { return m_dc; }
    virtual const std::weak_ptr<tgl_session>& get_session() const override { return m_session; }

    virtual void on_online_status_changed(tgl_online_status status) override;

private:
    bool is_online() const { return m_online_status == tgl_online_status::wwan_online || m_online_status == tgl_online_status::non_wwan_online; }
    bool connect();
    void schedule_restart();
    void restart(const boost::system::error_code& error);
    void start_ping_timer();
    void start_read();
    void handle_read(const std::shared_ptr<std::vector<char>>& buffer, const boost::system::error_code&, size_t);

    void start_write();
    void handle_write(const std::vector<std::shared_ptr<std::vector<char>>>& buffers, const boost::system::error_code&, size_t);

    void stop_ping_timer();
    void ping(const boost::system::error_code&);

    ssize_t read_in_lookup(void *data, size_t len);
    void try_rpc_read();

    void handle_connect(const boost::system::error_code&);
    void clear_buffers();

    std::string m_ip;
    int m_port;
    enum conn_state m_state;
    boost::asio::io_service& m_io_service;
    boost::asio::ip::tcp::socket m_socket;
    boost::asio::deadline_timer m_ping_timer;
    std::chrono::time_point<std::chrono::steady_clock>  m_last_receive_time;

    std::unique_ptr<boost::asio::deadline_timer> m_restart_timer;
    std::chrono::time_point<std::chrono::steady_clock> m_last_restart_time;
    std::chrono::milliseconds m_restart_duration;

    std::deque<std::shared_ptr<std::vector<char>>> m_write_buffer_queue;
    std::deque<std::shared_ptr<std::vector<char>>> m_read_buffer_queue;
    std::shared_ptr<std::vector<char>> m_temp_read_buffer;
    size_t m_in_bytes;
    std::weak_ptr<tgl_dc> m_dc;
    std::weak_ptr<tgl_session> m_session;
    std::shared_ptr<mtproto_client> m_mtproto_client;

    bool m_write_pending;
    tgl_online_status m_online_status;
};

class tgl_connection_factory_asio : public tgl_connection_factory
{
public:
    explicit tgl_connection_factory_asio(boost::asio::io_service& io_service)
        : m_io_service(io_service)
    { }

    virtual std::shared_ptr<tgl_connection> create_connection(
            const std::string& host,
            int port,
            const std::weak_ptr<tgl_session>& session,
            const std::weak_ptr<tgl_dc>& dc,
            const std::shared_ptr<mtproto_client>& client) override
    {
        return std::make_shared<tgl_connection_asio>(m_io_service,
                host, port, session, dc, client);
    }

private:
    boost::asio::io_service& m_io_service;
};

#endif
