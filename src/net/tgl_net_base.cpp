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

#include <tgl/impl/tgl_net_base.h>

#include <tgl/tgl_log.h>
#include <tgl/tgl_mtproto_client.h>
#include <tgl/tgl_connection_status.h>

// This is a default base implementation of tgl_connection. It should include the public headers only.

constexpr std::chrono::seconds PING_CHECK_DURATION(10);

constexpr std::chrono::milliseconds MIN_RESTART_DURATION(250);
constexpr std::chrono::milliseconds MAX_RESTART_DURATION(59000); // a little bit less than PING_FAIL_DURATION
constexpr std::chrono::milliseconds PING_DURATION(30000);
constexpr std::chrono::milliseconds PING_FAIL_DURATION(60000);

tgl_connection_base::tgl_connection_base(
        const std::vector<std::pair<std::string, int>>& ipv4_options,
        const std::vector<std::pair<std::string, int>>& ipv6_options,
        const std::weak_ptr<tgl_mtproto_client>& weak_client)
    : m_state(connection_state::none)
    , m_ping_timer()
    , m_last_receive_time()
    , m_restart_timer()
    , m_last_restart_time()
    , m_restart_duration(MIN_RESTART_DURATION)
    , m_available_bytes_for_read(0)
    , m_mtproto_client(weak_client)
    , m_online_status(tgl_online_status::not_online)
    , m_connection_status(tgl_connection_status::disconnected)
    , m_destructing(false)
{
    if (auto client = weak_client.lock()) {
        m_online_status = client->online_status();
        m_timer_factory = client->timer_factory();
    }
    m_ipv4_address = std::get<0>(ipv4_options[0]);
    m_ipv4_port = std::get<1>(ipv4_options[0]);
    m_ipv6_address = std::get<0>(ipv6_options[0]);
    m_ipv6_port = std::get<1>(ipv6_options[0]);
}

tgl_connection_base::~tgl_connection_base()
{
    m_destructing = true;

    // In the destructor we can not call disconnect() which is a pure virtual function.
    close_internal(false);

    if (auto client = m_mtproto_client.lock()) {
         TGL_DEBUG("connection to mtproto_client " << client->id() << " destroyed");
    }
}

void tgl_connection_base::ping()
{
    auto duration_since_last_receive = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - m_last_receive_time);
    if (duration_since_last_receive > PING_FAIL_DURATION) {
        TGL_WARNING("connection failed or ping timeout, scheduling restart");
        set_state(connection_state::failed);
        schedule_restart();
    } else if (duration_since_last_receive > PING_DURATION && m_state == connection_state::ready) {
        auto client = m_mtproto_client.lock();
        if (!client) {
            close();
            return;
        }
        client->ping();
        start_ping_timer();
    } else {
        start_ping_timer();
    }
}

void tgl_connection_base::stop_ping_timer()
{
    if (m_ping_timer) {
        m_ping_timer->cancel();
    }
}

void tgl_connection_base::start_ping_timer()
{
    stop_ping_timer();
    if (!m_ping_timer && m_timer_factory) {
        m_ping_timer = m_timer_factory->create_timer(std::bind(&tgl_connection_base::ping, shared_from_this()));
    }

    if (m_ping_timer) {
        m_ping_timer->start(PING_CHECK_DURATION.count());
    }
}

ssize_t tgl_connection_base::peek(void* data_out, size_t len)
{
    unsigned char* data = static_cast<unsigned char*>(data_out);
    if (!len || !m_available_bytes_for_read) {
        return 0;
    }
    assert(len > 0);
    if (len > m_available_bytes_for_read) {
        len = m_available_bytes_for_read;
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

void tgl_connection_base::open()
{
    m_this_weak_observer = shared_from_this();

    if (auto client = m_mtproto_client.lock()) {
        client->add_online_status_observer(m_this_weak_observer);
    }

    if (m_state == connection_state::closed) {
        return;
    }

    set_state(connection_state::connecting);

    if (!connect()) {
        if (m_state != connection_state::closed) {
            TGL_ERROR("failed to open connection");
            set_state(connection_state::failed);
            schedule_restart();
        }
        return;
    }

    char byte = 0xef;
    ssize_t result = write(&byte, 1);
    TGL_ASSERT_UNUSED(result, result == 1);
    flush();
}

void tgl_connection_base::connect_finished(bool success)
{
    auto client = m_mtproto_client.lock();
    if (!client) {
        close();
        return;
    }

    if (!success) {
        set_state(connection_state::failed);
        schedule_restart();
        return;
    }

    set_state(connection_state::ready);

    client->ping();
    start_ping_timer();
    m_restart_duration = MIN_RESTART_DURATION;

    m_last_receive_time = std::chrono::steady_clock::now();
}

void tgl_connection_base::lost()
{
    TGL_WARNING("connection lost, scheduling restart of the connection");
    schedule_restart();
}

void tgl_connection_base::error()
{
    set_state(connection_state::failed);
    schedule_restart();
}


void tgl_connection_base::schedule_restart()
{
    if (m_state == connection_state::closed) {
        TGL_WARNING("can not restart a closed connection");
        return;
    }

    if (m_state == connection_state::connecting) {
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

    if (m_timer_factory) {
        m_restart_timer = m_timer_factory->create_timer(std::bind(&tgl_connection_base::restart, shared_from_this()));
        m_restart_timer->start(timeout.count() / 1000.0);
    }
}

void tgl_connection_base::restart()
{
    m_restart_timer.reset();

    m_last_restart_time = std::chrono::steady_clock::now();

    stop_ping_timer();
    clear_buffers();
    disconnect();
    set_state(connection_state::failed);

    TGL_NOTICE("restarting connection");
    open();
}

void tgl_connection_base::try_read()
{
    if (m_state == connection_state::closed) {
        return;
    }
    start_read();
}

void tgl_connection_base::try_write()
{
    if (m_state == connection_state::closed) {
        return;
    }
    start_write();
}

void tgl_connection_base::consume_data()
{
    if (m_state == connection_state::closed) {
        return;
    }

    auto client = m_mtproto_client.lock();
    if (!client) {
        close();
        return;
    }

    if (!client->try_rpc_execute(shared_from_this()) && m_state != connection_state::closed) {
        set_state(connection_state::failed);
        schedule_restart();
    }
}

void tgl_connection_base::close()
{
    assert(!m_destructing);
    close_internal(true);
}

void tgl_connection_base::close_internal(bool call_disconnect)
{
    if (m_state == connection_state::closed) {
        return;
    }

    if (auto client = m_mtproto_client.lock()) {
        TGL_DEBUG("connection to mtproto_client " << client->id() << " closed");
        client->remove_online_status_observer(m_this_weak_observer);
    }

    set_state(connection_state::closed);
    stop_ping_timer();
    clear_buffers();

    if (call_disconnect) {
        disconnect();
    }
}

void tgl_connection_base::clear_buffers()
{
    m_write_buffer_queue.clear();
    m_read_buffer_queue.clear();
    m_available_bytes_for_read = 0;
}

void tgl_connection_base::data_received(const std::shared_ptr<tgl_net_buffer>& buffer)
{
    bytes_received(buffer->size());

    if (m_state == connection_state::closed) {
        TGL_WARNING("invalid read from closed connection");
        return;
    }

    if (auto client = m_mtproto_client.lock()) {
        TGL_DEBUG("received " << buffer->size() << " bytes from mtproto_client " << client->id());
    } else {
        TGL_DEBUG("received " << buffer->size() << " bytes");
    }

    if (buffer->size() > 0) {
        m_last_receive_time = std::chrono::steady_clock::now();
        stop_ping_timer();
        start_ping_timer();
        m_read_buffer_queue.push_back(buffer);
    }

    m_available_bytes_for_read += buffer->size();
    if (m_read_buffer_queue.size()) {
        consume_data();
    }
}

ssize_t tgl_connection_base::read(void* data_out, size_t len)
{
    unsigned char* data = static_cast<unsigned char*>(data_out);
    if (!len) {
        return 0;
    }

    assert(len > 0);
    if (len > m_available_bytes_for_read) {
        len = m_available_bytes_for_read;
    }

    size_t read_bytes = 0;
    auto buffer = m_read_buffer_queue.front();
    while (len) {
        size_t buffer_size = buffer->size();
        if (buffer_size >= len) {
            memcpy(data, buffer->data(), len);
            buffer->advance(len);
            if (buffer->empty()) {
                m_read_buffer_queue.pop_front();
            }
            m_available_bytes_for_read -= len;
            return read_bytes + len;
        } else {
            memcpy(data, buffer->data(), buffer_size);
            m_available_bytes_for_read -= buffer_size;
            read_bytes += buffer_size;
            data += buffer_size;
            len -= buffer_size;
            m_read_buffer_queue.pop_front();
            buffer = m_read_buffer_queue.front();
        }
    }

    return read_bytes;
}

ssize_t tgl_connection_base::write(const void* data, size_t len)
{
    if (!len) {
        return 0;
    }

    m_write_buffer_queue.push_back(std::make_shared<tgl_net_buffer>(static_cast<const char*>(data), len));
    try_write();
    return len;
}

void tgl_connection_base::flush()
{
}

void tgl_connection_base::on_online_status_changed(tgl_online_status status)
{
    if (m_online_status == status) {
        return;
    }

    m_online_status = status;

    if (m_state == connection_state::closed || !is_online()) {
        return;
    }

    set_state(connection_state::failed);
    m_restart_timer.reset();
    m_restart_duration = MIN_RESTART_DURATION;
    schedule_restart();
}

void tgl_connection_base::set_state(connection_state state)
{
    if (state == m_state) {
        return;
    }

    m_state = state;

    switch (m_state) {
    case connection_state::connecting:
        m_connection_status = tgl_connection_status::connecting;
        break;
    case connection_state::ready:
        m_connection_status = tgl_connection_status::connected;
        break;
    case connection_state::closed:
        m_connection_status = tgl_connection_status::closed;
        break;
    default:
        m_connection_status = tgl_connection_status::disconnected;
        break;
    }

    if (auto client = m_mtproto_client.lock()) {
        client->connection_status_changed(shared_from_this());
    }
}

bool tgl_connection_base::ipv6_enabled() const
{
    if (auto client = m_mtproto_client.lock()) {
        return client->ipv6_enabled();
    }
    return true;
}

void tgl_connection_base::bytes_sent(size_t bytes)
{
    if (auto client = m_mtproto_client.lock()) {
        client->bytes_sent(bytes);
    }
}

void tgl_connection_base::bytes_received(size_t bytes)
{
    if (auto client = m_mtproto_client.lock()) {
        client->bytes_received(bytes);
    }
}
