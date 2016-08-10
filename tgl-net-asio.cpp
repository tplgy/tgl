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

#include "tgl-net-asio.h"

#include "tgl-log.h"
#include "mtproto-client.h"
#include "types/tgl_connection_status.h"
#include "types/tgl_update_callback.h"

#include "tools.h"

constexpr size_t TEMP_READ_BUFFER_SIZE = 1024 * 1024;
constexpr std::chrono::milliseconds MIN_RESTART_DURATION(250);
constexpr std::chrono::milliseconds MAX_RESTART_DURATION(59000); // a little bit less than PING_FAIL_DURATION
constexpr std::chrono::milliseconds PING_CHECK_DURATION(10000);
constexpr std::chrono::milliseconds PING_DURATION(30000);
constexpr std::chrono::milliseconds PING_FAIL_DURATION(60000);

tgl_connection_asio::tgl_connection_asio(boost::asio::io_service& io_service,
        const std::weak_ptr<tgl_session>& session,
        const std::weak_ptr<tgl_dc>& dc,
        const std::shared_ptr<mtproto_client>& client)
    : m_state(conn_none)
    , m_io_service(io_service)
    , m_socket(io_service)
    , m_ping_timer(io_service)
    , m_last_receive_time()
    , m_restart_timer()
    , m_last_restart_time()
    , m_restart_duration(MIN_RESTART_DURATION)
    , m_in_bytes(0)
    , m_dc(dc)
    , m_session(session)
    , m_mtproto_client(client)
    , m_write_pending(false)
    , m_online_status(tgl_state::instance()->online_status())
{
    update_endpoint();
}

tgl_connection_asio::~tgl_connection_asio()
{
    close();
}

void tgl_connection_asio::ping(const boost::system::error_code& error) {
    if (error == boost::asio::error::operation_aborted) {
        return;
    }

    auto duration_since_last_receive = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - m_last_receive_time);
    if (duration_since_last_receive > PING_FAIL_DURATION) {
        TGL_WARNING("connection failed or ping timeout, scheduling restart");
        set_state(conn_failed);
        schedule_restart();
    } else if (duration_since_last_receive > PING_DURATION && m_state == conn_ready) {
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
    m_ping_timer.expires_from_now(boost::posix_time::milliseconds(PING_CHECK_DURATION.count()));
    m_ping_timer.async_wait(std::bind(&tgl_connection_asio::ping, shared_from_this(), std::placeholders::_1));
}

ssize_t tgl_connection_asio::read_in_lookup(void* data_out, size_t len) {
    unsigned char* data = static_cast<unsigned char*>(data_out);
    if (!len || !m_in_bytes) {
        return 0;
    }
    assert(len > 0);
    if (len > m_in_bytes) {
        len = m_in_bytes;
    }

    int read_bytes = 0;
    size_t i = 0;
    auto buffer = m_read_buffer_queue[i];
    while (len) {
        size_t buffer_size = buffer->size();
        if (buffer_size >= len) {
            memcpy(data, buffer->data(), len);
            return read_bytes + len;
        } else {
            memcpy(data, buffer->data(), buffer_size);
            read_bytes += buffer_size;
            data += buffer_size;
            len -= buffer_size;
            buffer = m_read_buffer_queue[++i];
        }
    }

    return read_bytes;
}

void tgl_connection_asio::open()
{
    tgl_state::instance()->add_online_status_observer(shared_from_this());
    if (!connect()) {
        TGL_ERROR("can not connect to " << m_endpoint);
        return;
    }

    char byte = 0xef; // use abridged protocol
    ssize_t result = write(&byte, 1);
    TGL_ASSERT_UNUSED(result, result == 1);
    flush();
}

void tgl_connection_asio::schedule_restart()
{
    if (m_state == conn_closed) {
        TGL_WARNING("can not restart a closed connection");
        return;
    }

    if (m_state == conn_connecting) {
        TGL_DEBUG("restart is already in process");
        return;
    }

    if (!is_online()) {
        TGL_NOTICE("not restarting because we are offline");
        return;
    }

    if (m_restart_timer) {
        return;
    }

    auto duration_since_last_restart = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - m_last_restart_time);
    std::chrono::milliseconds timeout(0);
    if (duration_since_last_restart < m_restart_duration) {
        timeout = m_restart_duration - duration_since_last_restart;
        m_restart_duration *= 2;
        if (m_restart_duration > MAX_RESTART_DURATION) {
            m_restart_duration = MAX_RESTART_DURATION;
        }
    }

    m_restart_timer.reset(new boost::asio::deadline_timer(m_io_service));
    m_restart_timer->expires_from_now(boost::posix_time::milliseconds(timeout.count()));
    m_restart_timer->async_wait(std::bind(&tgl_connection_asio::restart, shared_from_this(), std::placeholders::_1));
}

void tgl_connection_asio::restart(const boost::system::error_code& error)
{
    m_restart_timer.reset();
    if (error == boost::asio::error::operation_aborted) {
        return;
    }

    m_last_restart_time = std::chrono::steady_clock::now();

    stop_ping_timer();
    clear_buffers();
    set_state(conn_failed);
    if (m_socket.is_open()) {
        m_socket.close();
    }

    TGL_NOTICE("restarting connection to " << m_endpoint);
    open();
}

void tgl_connection_asio::try_rpc_read() {
    if (m_state == conn_closed) {
        return;
    }

    while (true) {
        if (m_in_bytes < 1) {
            return;
        }
        unsigned len = 0;
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
            unsigned t = 0;
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
        switch (m_mtproto_client->execute(shared_from_this(), op, len)) {
        case mtproto_client::execute_result::ok:
            break;
        case mtproto_client::execute_result::bad_session:
            // The client has already handled this case
            // and the connection should be closed.
            assert(m_state == conn_closed);
            break;
        case mtproto_client::execute_result::bad_connection:
            if (m_state != conn_closed) {
                set_state(conn_failed);
                schedule_restart();
            }
            break;
        case mtproto_client::execute_result::bad_dc:
            close();
            break;
        }
    }
}

void tgl_connection_asio::close()
{
    if (m_state == conn_closed) {
        return;
    }

    tgl_state::instance()->remove_online_status_observer(shared_from_this());
    m_mtproto_client->close(shared_from_this());
    set_state(conn_closed);
    m_ping_timer.cancel();
    m_socket.close();
    clear_buffers();
}

void tgl_connection_asio::clear_buffers()
{
    m_write_buffer_queue.clear();
    m_read_buffer_queue.clear();
    m_in_bytes = 0;
}

bool tgl_connection_asio::connect() {
    if (m_state == conn_closed) {
        return false;
    }

    start_ping_timer();
    set_state(conn_connecting);

    boost::system::error_code ec;
    m_socket.open(m_endpoint.protocol(), ec);
    if (ec) {
        TGL_WARNING("error opening socket: " << ec.message());
        return false;
    }

    m_socket.set_option(boost::asio::socket_base::keep_alive(true), ec);
    if (ec) {
        TGL_WARNING("error enabling keep-alives on socket: " << ec.message());
    }

    m_socket.set_option(boost::asio::ip::tcp::no_delay(true), ec);
    if (ec) {
        TGL_WARNING("error disabling Nagle algorithm on socket: " << ec.message());
    }

    m_socket.non_blocking(true, ec);
    if (ec) {
        TGL_WARNING("error making socket non-blocking: " << ec.message());
        return false;
    }

    m_socket.async_connect(m_endpoint, std::bind(&tgl_connection_asio::handle_connect, shared_from_this(), std::placeholders::_1));
    m_write_pending = false;
    m_last_receive_time = std::chrono::steady_clock::now();
    return true;
}

void tgl_connection_asio::handle_connect(const boost::system::error_code& ec)
{
    if (ec) {
        if (ec != boost::asio::error::operation_aborted) {
            TGL_WARNING("error connecting to " << m_endpoint << ": " << ec.value() << " - "<< ec.message());
            set_state(conn_failed);
            update_endpoint(true);
            schedule_restart();
        }
        return;
    }

    m_restart_duration = MIN_RESTART_DURATION;

    if (m_state == conn_connecting) {
        set_state(conn_ready);
        m_mtproto_client->ready(shared_from_this());
    } else {
        return;
    }

    TGL_NOTICE("connected to " << m_endpoint);

    m_last_receive_time = std::chrono::steady_clock::now();
    m_io_service.post(std::bind(&tgl_connection_asio::start_read, shared_from_this()));
}

ssize_t tgl_connection_asio::read(void* data_out, size_t len) {
    unsigned char* data = static_cast<unsigned char*>(data_out);
    if (!len) {
        return 0;
    }

    assert(len > 0);
    if (len > m_in_bytes) {
        len = m_in_bytes;
    }

    size_t read_bytes = 0;
    auto buffer = m_read_buffer_queue.front();
    while (len) {
        size_t buffer_size = buffer->size();
        if (buffer_size >= len) {
            memcpy(data, buffer->data(), len);
            if (buffer_size == len) {
                m_read_buffer_queue.pop_front();
            } else {
                memmove(buffer->data(), buffer->data() + len, buffer_size - len);
                buffer->resize(buffer_size - len);
            }
            m_in_bytes -= len;
            return read_bytes + len;
        } else {
            memcpy(data, buffer->data(), buffer_size);
            m_in_bytes -= buffer_size;
            read_bytes += buffer_size;
            data += buffer_size;
            len -= buffer_size;
            m_read_buffer_queue.pop_front();
            buffer = m_read_buffer_queue.front();
        }
    }

    return read_bytes;
}

void tgl_connection_asio::start_read() {
    if (m_state == conn_closed) {
        return;
    }

    m_temp_read_buffer = std::make_shared<std::vector<char>>(TEMP_READ_BUFFER_SIZE);

    m_socket.async_read_some(boost::asio::buffer(m_temp_read_buffer->data(), m_temp_read_buffer->size()),
            std::bind(&tgl_connection_asio::handle_read, shared_from_this(), m_temp_read_buffer, std::placeholders::_1, std::placeholders::_2));
}

ssize_t tgl_connection_asio::write(const void* data_in, size_t len) {
    //TGL_DEBUG("write: " << len << " bytes to DC " << m_dc.lock()->id);
    const unsigned char* data = static_cast<const unsigned char*>(data_in);
    if (!len) {
        return 0;
    }

    auto buffer = std::make_shared<std::vector<char>>(len);
    memcpy(buffer->data(), data, len);
    m_write_buffer_queue.push_back(buffer);

    if (!m_write_pending) {
        m_io_service.post(std::bind(&tgl_connection_asio::start_write, shared_from_this()));
    }

    return len;
}

void tgl_connection_asio::start_write() {
    if (m_state == conn_closed) {
        return;
    }

    if (!m_write_pending && m_write_buffer_queue.size() > 0) {
        m_write_pending = true;
        std::vector<boost::asio::const_buffer> buffers;
        std::vector<std::shared_ptr<std::vector<char>>> pending_buffers;
        for (const auto& buffer: m_write_buffer_queue) {
            buffers.push_back(boost::asio::buffer(buffer->data(), buffer->size()));
            pending_buffers.push_back(buffer);
        }
        boost::asio::async_write(m_socket, buffers,
                std::bind(&tgl_connection_asio::handle_write, shared_from_this(), pending_buffers, std::placeholders::_1, std::placeholders::_2));
    }
}

void tgl_connection_asio::flush() {
}

void tgl_connection_asio::handle_read(const std::shared_ptr<std::vector<char>>& buffer,
        const boost::system::error_code& ec, size_t bytes_transferred) {
    if (m_temp_read_buffer != buffer) {
        TGL_DEBUG("the temp reading buffer has changed due to connection restart");
        return;
    }

    if (ec) {
        if (ec != boost::asio::error::operation_aborted) {
            TGL_WARNING("read error: " << ec << " (" << ec.message() << ")");
            schedule_restart();
        }
        return;
    }

    if (m_state == conn_closed) {
        TGL_WARNING("invalid read from closed connection");
        return;
    }

    TGL_DEBUG("received " << bytes_transferred << " bytes");

    if (bytes_transferred > 0) {
        m_last_receive_time = std::chrono::steady_clock::now();
        stop_ping_timer();
        start_ping_timer();

        if (bytes_transferred != buffer->size()) {
            assert(bytes_transferred < buffer->size());
            buffer->resize(bytes_transferred);
        }
        m_read_buffer_queue.push_back(buffer);
    }

    m_in_bytes += bytes_transferred;
    if (m_read_buffer_queue.size()) {
        try_rpc_read();
    }

    start_read();
}

static inline bool starts_with_buffers(const std::deque<std::shared_ptr<std::vector<char>>>& queue,
        const std::vector<std::shared_ptr<std::vector<char>>>& buffers)
{
    if (queue.size() < buffers.size()) {
        return false;
    }

    size_t i = 0;
    for (const auto& buffer: buffers) {
        if (buffer != queue[i++]) {
            return false;
        }
    }

    return true;
}

void tgl_connection_asio::handle_write(const std::vector<std::shared_ptr<std::vector<char>>>& buffers,
        const boost::system::error_code& ec, size_t bytes_transferred) {
    if (!starts_with_buffers(m_write_buffer_queue, buffers)) {
        TGL_DEBUG("the front writing buffers have changed due to connection restart");
        return;
    }

    m_write_pending = false;
    m_write_buffer_queue.erase(m_write_buffer_queue.begin(), m_write_buffer_queue.begin() + buffers.size());

    if (ec) {
        if (ec != boost::asio::error::operation_aborted) {
            TGL_WARNING("write error: " << ec << " (" << ec.message() << ")");
            schedule_restart();
        }
        return;
    }

    if (m_state == conn_closed) {
        TGL_WARNING("invalid write to closed connection");
        return;
    }

    //TGL_DEBUG("wrote " << bytes_transferred << " bytes to DC " << m_dc.lock()->id);

    if (m_write_buffer_queue.size() > 0) {
        m_io_service.post(std::bind(&tgl_connection_asio::start_write, shared_from_this()));
    }
}

void tgl_connection_asio::on_online_status_changed(tgl_online_status status)
{
    if (m_online_status == status) {
        return;
    }

    m_online_status = status;

    if (m_state == conn_closed || !is_online()) {
        return;
    }

    set_state(conn_failed);
    m_restart_timer.reset();
    m_restart_duration = MIN_RESTART_DURATION;
    schedule_restart();
}

void tgl_connection_asio::set_state(conn_state state)
{
    if (state == m_state) {
        return;
    }

    m_state = state;

    auto dc = m_dc.lock();
    if (!dc || dc != tgl_state::instance()->working_dc()) {
        return;
    }

    tgl_connection_status status;
    switch (m_state) {
    case conn_connecting:
        status = tgl_connection_status::connecting;
        break;
    case conn_ready:
        status = tgl_connection_status::connected;
        break;
    default:
        status = tgl_connection_status::disconnected;
        break;
    }

    tgl_state::instance()->callback()->connection_status_changed(status);
}

void tgl_connection_asio::update_endpoint(bool due_to_failed_connection)
{
    auto data_center = m_dc.lock();
    if (!data_center) {
        TGL_WARNING("the dc object has gone");
        return;
    }

    if (tgl_state::instance()->ipv6_enabled()
            && !(due_to_failed_connection && m_endpoint.protocol() == boost::asio::ip::tcp::v6())) {
        m_endpoint = boost::asio::ip::tcp::endpoint(
                boost::asio::ip::address::from_string(std::get<0>(data_center->ipv6_options.option_list[0])),
                std::get<1>(data_center->ipv6_options.option_list[0]));
    } else {
        m_endpoint = boost::asio::ip::tcp::endpoint(
                boost::asio::ip::address::from_string(std::get<0>(data_center->ipv4_options.option_list[0])),
                std::get<1>(data_center->ipv4_options.option_list[0]));
    }
}
