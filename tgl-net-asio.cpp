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

#include <boost/bind.hpp>

#include "tgl-net-asio.h"

#include "tgl-log.h"
#include "mtproto-client.h"

extern "C" {
#include "tools.h"
}

#define PING_TIMEOUT 10

tgl_connection_asio::tgl_connection_asio(boost::asio::io_service& io_service,
        const std::string& host, int port,
        const std::weak_ptr<tgl_session>& session,
        const std::weak_ptr<tgl_dc>& dc,
        const std::shared_ptr<mtproto_client>& client)
    : m_closed(false)
    , m_ip(host)
    , m_port(port)
    , m_state(conn_none)
    , m_io_service(io_service)
    , m_socket(io_service)
    , m_ping_timer(io_service)
    , m_fail_timer(io_service)
    , m_out_packet_num(0)
    , m_in_head(nullptr)
    , m_in_tail(nullptr)
    , m_out_head(nullptr)
    , m_out_tail(nullptr)
    , m_in_bytes(0)
    , m_bytes_to_write(0)
    , m_dc(dc)
    , m_session(session)
    , m_mtproto_client(client)
    , m_last_connect_time(0)
    , m_last_receive_time(0)
    , m_in_fail_timer(false)
    , m_write_pending(false)
{
}

tgl_connection_asio::~tgl_connection_asio()
{
    free_buffers();
}

void tgl_connection_asio::ping_alarm(const boost::system::error_code& error) {
    if (error == boost::asio::error::operation_aborted) {
        return;
    }
    if (m_state == conn_failed) {
        return;
    }
    //TGL_DEBUG("ping alarm");
    TGL_ASSERT(m_state == conn_ready || m_state == conn_connecting);
    if (tglt_get_double_time() - m_last_receive_time > 6 * PING_TIMEOUT) {
        TGL_WARNING("fail connection: reason: ping timeout");
        m_state = conn_failed;
        fail();
    } else if (tglt_get_double_time() - m_last_receive_time > 3 * PING_TIMEOUT && m_state == conn_ready) {
        tgl_do_send_ping(shared_from_this());
        start_ping_timer();
    } else {
        start_ping_timer();
    }
}

void tgl_connection_asio::stop_ping_timer() {
    m_ping_timer.cancel();
}

void tgl_connection_asio::start_ping_timer() {
    m_ping_timer.expires_from_now(boost::posix_time::seconds(PING_TIMEOUT));
    m_ping_timer.async_wait(boost::bind(&tgl_connection_asio::ping_alarm, shared_from_this(), boost::asio::placeholders::error));
}

void tgl_connection_asio::fail_alarm(const boost::system::error_code& error) {
    m_in_fail_timer = false;
    if (error == boost::asio::error::operation_aborted) {
        return;
    }
    restart();
}

void tgl_connection_asio::start_fail_timer() {
    if (m_in_fail_timer) {
        return;
    }
    m_in_fail_timer = true;

    m_fail_timer.expires_from_now(boost::posix_time::seconds(10));
    m_fail_timer.async_wait(boost::bind(&tgl_connection_asio::fail_alarm, shared_from_this(), boost::asio::placeholders::error));
}

static connection_buffer *new_connection_buffer(int size) {
    connection_buffer *b = (connection_buffer *)talloc0(sizeof(connection_buffer));
    b->start = (unsigned char*)malloc(size);
    b->end = b->start + size;
    b->rptr = b->wptr = b->start;
    return b;
}

static void delete_connection_buffer(connection_buffer *b) {
    free(b->start);
    free(b);
}

ssize_t tgl_connection_asio::read_in_lookup(void *_data, size_t len) {
    unsigned char *data = (unsigned char *)_data;
    if (!len || !m_in_bytes) { return 0; }
    assert (len > 0);
    if (len > m_in_bytes) {
        len = m_in_bytes;
    }
    int x = 0;
    connection_buffer *b = m_in_head;
    while (len) {
        size_t y = b->wptr - b->rptr;
        if (y >= len) {
            memcpy(data, b->rptr, len);
            return x + len;
        } else {
            memcpy(data, b->rptr, y);
            x += y;
            data += y;
            len -= y;
            b = b->next;
        }
    }
    return x;
}

static int rotate_port(int port) {
    switch (port) {
        case 443:
            return 80;
        case 80:
            return 25;
        case 25:
            return 443;
    }
    return -1;
}

bool tgl_connection_asio::open()
{
    if (!connect()) {
        TGL_ERROR("Can not connect to " << m_ip << ":" << m_port);
        return false;
    }

    start_ping_timer();

    char byte = 0xef; // use abridged protocol
    ssize_t result = write(&byte, 1);
    TGL_ASSERT_UNUSED(result, result == 1);
    flush();

    return true;
}

void tgl_connection_asio::restart() {
    if (m_closed) {
        TGL_WARNING("Can't restart a closed connection");
        return;
    }

    if (m_last_connect_time == time(0)) {
        start_fail_timer();
        return;
    }

    m_socket.close();
    m_last_connect_time = time(0);
    if (!connect()) {
        TGL_WARNING("Can not reconnect to " << m_ip << ":" << m_port);
        start_fail_timer();
        return;
    }

    TGL_DEBUG("restarting connection to " << m_ip << ":" << m_port);

    start_ping_timer();

    char byte = 0xef; // use abridged protocol
    ssize_t result = write(&byte, 1);
    TGL_ASSERT_UNUSED(result, result == 1);
    flush();
}

void tgl_connection_asio::fail() {
    if (m_state == conn_ready || m_state == conn_connecting) {
        stop_ping_timer();
    }

    if (m_socket.is_open()) {
        m_socket.close();
    }

    m_port = rotate_port(m_port);
    connection_buffer* b = m_out_head;
    while (b) {
        connection_buffer *d = b;
        b = b->next;
        delete_connection_buffer(d);
    }
    b = m_in_head;
    while (b) {
        connection_buffer *d = b;
        b = b->next;
        delete_connection_buffer(d);
    }
    m_out_head = m_out_tail = m_in_head = m_in_tail = nullptr;
    m_state = conn_failed;
    m_bytes_to_write = m_in_bytes = 0;
    TGL_NOTICE("Lost connection to server... " << m_ip << ":" << m_port);
    restart();
}

void tgl_connection_asio::try_rpc_read() {
    if (m_closed) {
        return;
    }

    TGL_ASSERT(m_in_head);

    while (1) {
        if (m_in_bytes < 1) { return; }
        unsigned len = 0;
        unsigned t = 0;
        ssize_t result = read_in_lookup(&len, 1);
        TGL_ASSERT_UNUSED(result, result == 1);
        if (len >= 1 && len <= 0x7e) {
            if (m_in_bytes < 1 + 4 * len) {
                return;
            }
        } else {
            if (m_in_bytes < 4) { return; }
            result = read_in_lookup(&len, 4);
            TGL_ASSERT_UNUSED(result, result == 4);
            len = (len >> 8);
            if (m_in_bytes < 4 + 4 * len) {
                return;
            }
            len = 0x7f;
        }

        if (len >= 1 && len <= 0x7e) {
            result = read(&t, 1);
            TGL_ASSERT_UNUSED(result, result == 1);
            TGL_ASSERT(t == len);
            TGL_ASSERT(len >= 1);
        } else {
            TGL_ASSERT(len == 0x7f);
            result = read(&len, 4);
            TGL_ASSERT_UNUSED(result, result == 4);
            len = (len >> 8);
            TGL_ASSERT(len >= 1);
        }
        len *= 4;
        int op;
        result = read_in_lookup(&op, 4);
        TGL_ASSERT_UNUSED(result, result == 4);
        if (m_mtproto_client->execute(shared_from_this(), op, len) < 0) {
            fail();
            return;
        }
    }
}

void tgl_connection_asio::close()
{
    if (m_closed) {
        return;
    }

    m_closed = true;
    m_ping_timer.cancel();
    m_fail_timer.cancel();
    m_socket.close();
    free_buffers();
}

void tgl_connection_asio::free_buffers()
{
    connection_buffer* b = m_out_head;
    while (b) {
        connection_buffer *d = b;
        b = b->next;
        delete_connection_buffer(d);
    }
    m_out_head = nullptr;
    m_out_tail = nullptr;
    m_bytes_to_write = 0;

    b = m_in_head;
    while (b) {
        connection_buffer *d = b;
        b = b->next;
        delete_connection_buffer(d);
    }
    m_in_head = nullptr;
    m_in_tail = nullptr;
    m_in_bytes = 0;
}

bool tgl_connection_asio::connect() {
    if (m_closed) {
        return false;
    }

    boost::system::error_code ec;
    m_socket.open(tgl_state::instance()->ipv6_enabled() ? boost::asio::ip::tcp::v6() : boost::asio::ip::tcp::v4(), ec);
    if (ec) {
        TGL_WARNING("error opening socket: " << ec.message());
        return false;
    }

    m_socket.set_option(boost::asio::socket_base::reuse_address(true));
    m_socket.set_option(boost::asio::socket_base::keep_alive(true));
    m_socket.set_option(boost::asio::ip::tcp::no_delay(true));
    m_socket.non_blocking(true, ec);
    if (ec) {
        TGL_WARNING("error making socket non-blocking: " << ec.message());
        return false;
    }

    boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::address::from_string(m_ip), m_port);
    m_socket.async_connect(endpoint, std::bind(&tgl_connection_asio::handle_connect, shared_from_this(), std::placeholders::_1));
    m_state = conn_connecting;
    m_last_receive_time = tglt_get_double_time();
    return true;
}

void tgl_connection_asio::handle_connect(const boost::system::error_code& ec)
{
    if (ec) {
        TGL_WARNING("error connecting to " << m_ip << ":" << m_port << ": " << ec.message());
        fail();
        return;
    }

    TGL_NOTICE("connected to " << m_ip << ":" << m_port);

    m_last_receive_time = tglt_get_double_time();
    m_io_service.post(boost::bind(&tgl_connection_asio::start_read, shared_from_this()));
}

ssize_t tgl_connection_asio::read(void* buffer, size_t len) {
    unsigned char* data = static_cast<unsigned char*>(buffer);
    if (!len) {
        return 0;
    }

    assert (len > 0);
    if (len > m_in_bytes) {
        len = m_in_bytes;
    }
    size_t x = 0;
    while (len) {
        size_t y = m_in_head->wptr - m_in_head->rptr;
        if (y > len) {
            memcpy (data, m_in_head->rptr, len);
            m_in_head->rptr += len;
            m_in_bytes -= len;
            return x + len;
        } else {
            memcpy(data, m_in_head->rptr, y);
            m_in_bytes -= y;
            x += y;
            data += y;
            len -= y;
            connection_buffer *old = m_in_head;
            m_in_head = m_in_head->next;
            if (!m_in_head) {
                m_in_tail = nullptr;
            }
            delete_connection_buffer(old);
        }
    }
    return x;
}

void tgl_connection_asio::start_read() {
    if (m_closed) {
        return;
    }

    if (!m_in_tail) {
        m_in_head = m_in_tail = new_connection_buffer(1 << 20);
    }

    m_socket.async_receive(boost::asio::buffer(m_in_tail->wptr, m_in_tail->end - m_in_tail->wptr),
            boost::bind(&tgl_connection_asio::handle_read, shared_from_this(),
                boost::asio::placeholders::error,
                boost::asio::placeholders::bytes_transferred));
}

ssize_t tgl_connection_asio::write(const void* data_in, size_t len) {
    //TGL_DEBUG("write: " << len << " bytes");
    const unsigned char* data = static_cast<const unsigned char*>(data_in);
    if (!len) {
        return 0;
    }
    assert (len > 0);
    size_t x = 0;
    if (!m_out_head) {
        connection_buffer *b = new_connection_buffer(1 << 20);
        m_out_head = m_out_tail = b;
    }
    while (len) {
        if (static_cast<size_t>(m_out_tail->end - m_out_tail->wptr) >= len) {
            memcpy(m_out_tail->wptr, data, len);
            m_out_tail->wptr += len;
            m_bytes_to_write += len;
            x += len;
            break;
        } else {
            size_t y = m_out_tail->end - m_out_tail->wptr;
            TGL_ASSERT(y < len);
            memcpy(m_out_tail->wptr, data, y);
            x += y;
            len -= y;
            data += y;
            connection_buffer *b = new_connection_buffer (1 << 20);
            m_out_tail->next = b;
            b->next = nullptr;
            m_out_tail = b;
            m_bytes_to_write += y;
        }
    }
    if (m_bytes_to_write) {
        m_io_service.post(boost::bind(&tgl_connection_asio::start_write, shared_from_this()));
    }
    return x;
}

void tgl_connection_asio::start_write() {
    if (m_closed) {
        return;
    }

    if (m_state == conn_connecting) {
        m_state = conn_ready;
        m_mtproto_client->ready(shared_from_this());
    }

    if (!m_write_pending && m_bytes_to_write > 0) {
        m_write_pending = true;
        TGL_ASSERT(m_out_head);
        m_socket.async_send(boost::asio::buffer(m_out_head->rptr, m_out_head->wptr - m_out_head->rptr),
                boost::bind(&tgl_connection_asio::handle_write, shared_from_this(),
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred));
    }
}

void tgl_connection_asio::flush() {
}

void tgl_connection_asio::handle_read(const boost::system::error_code& ec, size_t bytes_transferred) {
    if (ec) {
        if (ec != boost::asio::error::operation_aborted) {
            TGL_WARNING("read error: " << ec << " (" << ec.message() << ")");
            fail();
        }
        return;
    }

    if (m_closed) {
        TGL_WARNING("invalid read from closed connection");
        return;
    }

    TGL_DEBUG("received " << bytes_transferred << " bytes");

    if (bytes_transferred > 0) {
        m_last_receive_time = tglt_get_double_time();
        stop_ping_timer();
        start_ping_timer();
    }

    m_in_tail->wptr += bytes_transferred;
    if (m_in_tail->wptr == m_in_tail->end) {
        connection_buffer *b = new_connection_buffer(1 << 20);
        m_in_tail->next = b;
        m_in_tail = b;
    }

    m_in_bytes += bytes_transferred;
    if (bytes_transferred) {
        try_rpc_read();
    }

    start_read();
}

void tgl_connection_asio::handle_write(const boost::system::error_code& ec, size_t bytes_transferred) {
    m_write_pending = false;
    if (ec) {
        TGL_WARNING("write error: " << ec << " (" << ec.message() << ")");
        fail();
        return;
    }

    if (m_closed) {
        TGL_WARNING("invalid write to closed connection");
        return;
    }

    TGL_DEBUG("wrote " << bytes_transferred << " bytes");

    if (m_out_head) {
        m_out_head->rptr += bytes_transferred;
        if (m_out_head->rptr == m_out_head->wptr) {
            connection_buffer* b = m_out_head;
            m_out_head = b->next;
            if (!m_out_head) {
                m_out_tail = nullptr;
            }
            delete_connection_buffer(b);
        }
    }

    m_bytes_to_write -= bytes_transferred;
    if (m_bytes_to_write > 0) {
        m_io_service.post(boost::bind(&tgl_connection_asio::start_write, shared_from_this()));
    }
}
