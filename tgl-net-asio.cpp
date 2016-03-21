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
#include "tgl-timers.h"
#include "mtproto-client.h"

extern "C" {
#include "tools.h"
}

#define PING_TIMEOUT 10

void connection::ping_alarm(const boost::system::error_code& error) {
    if (error == boost::asio::error::operation_aborted) {
        return;
    }
    if (state == conn_failed) {
        return;
    }
    //TGL_DEBUG("ping alarm\n");
    assert(state == conn_ready || state == conn_connecting);
    if (tglt_get_double_time() - last_receive_time > 6 * PING_TIMEOUT) {
        TGL_WARNING("fail connection: reason: ping timeout\n");
        state = conn_failed;
        fail();
    } else if (tglt_get_double_time() - last_receive_time > 3 * PING_TIMEOUT && state == conn_ready) {
        tgl_do_send_ping(shared_from_this());
        start_ping_timer();
    } else {
        start_ping_timer();
    }
}

void connection::stop_ping_timer() {
    ping_timer.cancel();
}

void connection::start_ping_timer() {
    ping_timer.expires_from_now(boost::posix_time::seconds(PING_TIMEOUT));
    ping_timer.async_wait(boost::bind(&connection::ping_alarm, shared_from_this(), boost::asio::placeholders::error));
}

void connection::fail_alarm(const boost::system::error_code& error) {
    in_fail_timer = false;
    if (error == boost::asio::error::operation_aborted) {
        return;
    }
    restart();
}

void connection::start_fail_timer() {
    if (in_fail_timer) { return; }
    in_fail_timer = true;

    fail_timer.expires_from_now(boost::posix_time::seconds(10));
    fail_timer.async_wait(boost::bind(&connection::fail_alarm, shared_from_this(), boost::asio::placeholders::error));
}

static struct connection_buffer *new_connection_buffer(int size) {
    struct connection_buffer *b = (struct connection_buffer *)talloc0(sizeof(struct connection_buffer));
    b->start = (unsigned char*)malloc(size);
    b->end = b->start + size;
    b->rptr = b->wptr = b->start;
    return b;
}

static void delete_connection_buffer(struct connection_buffer *b) {
    tfree(b->start);
    tfree(b);
}

int tgln_write_out(std::shared_ptr<connection> c, const void *data, int len) {
    return c->write(data, len);
}

int tgln_read_in(std::shared_ptr<connection> c, void *buffer, int len) {
    return c->read(buffer, len);
}

int connection::read_in_lookup(void *_data, int len) {
    unsigned char *data = (unsigned char *)_data;
    if (!len || !in_bytes) { return 0; }
    assert (len > 0);
    if (len > in_bytes) {
        len = in_bytes;
    }
    int x = 0;
    struct connection_buffer *b = in_head;
    while (len) {
        int y = b->wptr - b->rptr;
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

void tgln_flush_out(std::shared_ptr<connection> c) {
    c->flush();
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

std::shared_ptr<connection> tgln_create_connection(const std::string &host, int port, std::shared_ptr<tgl_session> session, std::shared_ptr<tgl_dc> dc, struct mtproto_methods *methods) {
    std::shared_ptr<connection> c = std::make_shared<connection>(*tgl_state::instance()->io_service, host, port, session, dc, methods);

    if (!c->connect()) {
        TGL_ERROR("Can not connect to " << host << ":" << port << "\n");
        c = nullptr;
        return 0;
    }

    c->start_ping_timer();

    char byte = 0xef; // use abridged protocol
    assert(tgln_write_out(c, &byte, 1) == 1);
    tgln_flush_out(c);

    return c;
}

void connection::restart() {
    if (destroyed) {
        TGL_WARNING("Can't restart a destroyed connection" << std::endl);
        return;
    }

    if (last_connect_time == time(0)) {
        start_fail_timer();
        return;
    }

    socket.close();
    last_connect_time = time(0);
    if (!connect()) {
        TGL_WARNING("Can not reconnect to " << ip << ":" << port << "\n");
        start_fail_timer();
        return;
    }

    TGL_DEBUG("restarting connection to " << ip << ":" << port << "\n");

    //state = conn_connecting;
    last_receive_time = tglt_get_double_time();
    start_ping_timer();

    char byte = 0xef; // use abridged protocol
    assert(tgln_write_out(shared_from_this(), &byte, 1) == 1);
    tgln_flush_out(shared_from_this());
}

void connection::fail() {
    if (state == conn_ready || state == conn_connecting) {
        stop_ping_timer();
    }

    if (socket.is_open()) {
        socket.close();
    }

    port = rotate_port(port);
    struct connection_buffer *b = out_head;
    while (b) {
        struct connection_buffer *d = b;
        b = b->next;
        delete_connection_buffer(d);
    }
    b = in_head;
    while (b) {
        struct connection_buffer *d = b;
        b = b->next;
        delete_connection_buffer(d);
    }
    out_head = out_tail = in_head = in_tail = 0;
    state = conn_failed;
    bytes_to_write = in_bytes = 0;
    TGL_NOTICE("Lost connection to server... " << ip << ":" << port << "\n");
    restart();
}

void connection::try_rpc_read() {
    assert(in_head);

    while (1) {
        if (in_bytes < 1) { return; }
        unsigned len = 0;
        unsigned t = 0;
        assert(read_in_lookup(&len, 1) == 1);
        if (len >= 1 && len <= 0x7e) {
            if (in_bytes < (int)(1 + 4 * len)) { return; }
        } else {
            if (in_bytes < 4) { return; }
            assert(read_in_lookup(&len, 4) == 4);
            len = (len >> 8);
            if (in_bytes < (int)(4 + 4 * len)) { return; }
            len = 0x7f;
        }

        if (len >= 1 && len <= 0x7e) {
            assert(tgln_read_in(shared_from_this(), &t, 1) == 1);
            assert(t == len);
            assert(len >= 1);
        } else {
            assert(len == 0x7f);
            assert(tgln_read_in(shared_from_this(), &len, 4) == 4);
            len = (len >> 8);
            assert(len >= 1);
        }
        len *= 4;
        int op;
        assert(read_in_lookup(&op, 4) == 4);
        if (methods->execute(shared_from_this(), op, len) < 0) {
            fail();
            return;
        }
    }
}

static void incr_out_packet_num(std::shared_ptr<connection> c) {
    c->incr_out_packet_num();
}

static std::shared_ptr<tgl_dc> get_dc(std::shared_ptr<connection> c) {
    return c->dc();
}

static std::shared_ptr<tgl_session> get_session(std::shared_ptr<connection> c) {
    return c->session();
}

static void tgln_free(std::shared_ptr<connection> c) {
    c->destroy();
}

connection::connection(boost::asio::io_service& io_service, const std::string& host, int port, std::shared_ptr<tgl_session> session, std::shared_ptr<tgl_dc> dc, struct mtproto_methods *methods)
    : destroyed(false)
    , ip(host)
    , port(port)
    , state(conn_none)
    , socket(io_service)
    , ping_timer(io_service)
    , fail_timer(io_service)
    , out_packet_num(0)
    , in_head(nullptr)
    , in_tail(nullptr)
    , out_head(nullptr)
    , out_tail(nullptr)
    , in_bytes(0)
    , bytes_to_write(0)
    , _dc(dc)
    , methods(methods)
    , _session(session)
    , last_connect_time(0)
    , last_receive_time(0)
    , in_fail_timer(false)
    , write_pending(false)
{
}

void connection::destroy()
{
    destroyed = true;
    ping_timer.cancel();
    fail_timer.cancel();
    socket.close();

    struct connection_buffer *b = out_head;
    while (b) {
        struct connection_buffer *d = b;
        b = b->next;
        delete_connection_buffer(d);
    }
    b = in_head;
    while (b) {
        struct connection_buffer *d = b;
        b = b->next;
        delete_connection_buffer(d);
    }
}

bool connection::connect() {
    assert(!destroyed);

    boost::system::error_code ec;
    socket.open(tgl_state::instance()->ipv6_enabled() ? boost::asio::ip::tcp::v6() : boost::asio::ip::tcp::v4(), ec);
    if (ec) {
        TGL_WARNING("error opening socket: " << ec.message() << "\n");
        return false;
    }

    socket.set_option(boost::asio::socket_base::reuse_address(true));
    socket.set_option(boost::asio::socket_base::keep_alive(true));
    socket.set_option(boost::asio::ip::tcp::no_delay(true));
    socket.non_blocking(true, ec);
    if (ec) {
        TGL_WARNING("error making socket non-blocking: " << ec.message() << "\n");
        return false;
    }

    boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::address::from_string(ip), port);
    socket.connect(endpoint, ec);
    if (ec) {
        TGL_WARNING("error connecting to " << endpoint << ": " << ec.message() << "\n");
        return false;
    }
    TGL_NOTICE("connected to " << endpoint << "\n");
    state = conn_connecting;
    last_receive_time = tglt_get_double_time();
    tgl_state::instance()->io_service->post(boost::bind(&connection::start_read, shared_from_this()));
    return true;
}

int connection::read(void *buffer, int len) {
    assert(!destroyed);

    unsigned char *data = (unsigned char *)buffer;
    if (!len) { return 0; }
    assert (len > 0);
    if (len > in_bytes) {
        len = in_bytes;
    }
    int x = 0;
    while (len) {
        int y = in_head->wptr - in_head->rptr;
        if (y > len) {
            memcpy (data, in_head->rptr, len);
            in_head->rptr += len;
            in_bytes -= len;
            return x + len;
        } else {
            memcpy(data, in_head->rptr, y);
            in_bytes -= y;
            x += y;
            data += y;
            len -= y;
            struct connection_buffer *old = in_head;
            in_head = in_head->next;
            if (!in_head) {
                in_tail = 0;
            }
            delete_connection_buffer(old);
        }
    }
    return x;
}

void connection::start_read() {
    assert(!destroyed);

    if (!in_tail) {
        in_head = in_tail = new_connection_buffer(1 << 20);
    }

    socket.async_receive(boost::asio::buffer(in_tail->wptr, in_tail->end - in_tail->wptr),
            boost::bind(&connection::handle_read, shared_from_this(),
                boost::asio::placeholders::error,
                boost::asio::placeholders::bytes_transferred));
}

int connection::write(const void *_data, int len) {
    assert(!destroyed);

    //TGL_DEBUG("write: " << len << " bytes\n");
    const unsigned char *data = (const unsigned char *)_data;
    if (!len) { return 0; }
    assert (len > 0);
    int x = 0;
    if (!out_head) {
        struct connection_buffer *b = new_connection_buffer(1 << 20);
        out_head = out_tail = b;
    }
    while (len) {
        if (out_tail->end - out_tail->wptr >= len) {
            memcpy(out_tail->wptr, data, len);
            out_tail->wptr += len;
            bytes_to_write += len;
            x += len;
            break;
        } else {
            int y = out_tail->end - out_tail->wptr;
            assert(y < len);
            memcpy(out_tail->wptr, data, y);
            x += y;
            len -= y;
            data += y;
            struct connection_buffer *b = new_connection_buffer (1 << 20);
            out_tail->next = b;
            b->next = 0;
            out_tail = b;
            bytes_to_write += y;
        }
    }
    if (bytes_to_write) {
        tgl_state::instance()->io_service->post(boost::bind(&connection::start_write, shared_from_this()));
    }
    return x;
}

void connection::start_write() {
    assert(!destroyed);

    if (state == conn_connecting) {
        state = conn_ready;
        methods->ready(shared_from_this());
    }

    if (!write_pending && bytes_to_write > 0) {
        write_pending = true;
        assert(out_head);
        socket.async_send(boost::asio::buffer(out_head->rptr, out_head->wptr - out_head->rptr),
                boost::bind(&connection::handle_write, shared_from_this(),
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred));
    }
}

void connection::flush() {
    assert(!destroyed);
}

void connection::handle_read(const boost::system::error_code& ec, size_t bytes_transferred) {
    if (ec) {
        if (ec != boost::asio::error::operation_aborted) {
            TGL_WARNING("read error: " << ec << " (" << ec.message() << ")" << std::endl);
            fail();
        }
        return;
    }

    if (destroyed) {
        TGL_WARNING("invalid read from destroyed connection" << std::endl);
        return;
    }

    TGL_DEBUG("received " << bytes_transferred << " bytes" << std::endl);

    if (bytes_transferred > 0) {
        last_receive_time = tglt_get_double_time();
        stop_ping_timer();
        start_ping_timer();
    }

    in_tail->wptr += bytes_transferred;
    if (in_tail->wptr == in_tail->end) {
        struct connection_buffer *b = new_connection_buffer(1 << 20);
        in_tail->next = b;
        in_tail = b;
    }

    in_bytes += bytes_transferred;
    if (bytes_transferred) {
        try_rpc_read();
    }

    start_read();
}

void connection::handle_write(const boost::system::error_code& ec, size_t bytes_transferred) {
    write_pending = false;
    if (ec) {
        TGL_WARNING("write error: " << ec << " (" << ec.message() << ")" << std::endl);
        fail();
        return;
    }

    if (destroyed) {
        TGL_WARNING("invalid write to detroyed connection" << std::endl);
        return;
    }


    TGL_DEBUG("wrote " << bytes_transferred << " bytes" << std::endl);

    if (out_head) {
        out_head->rptr += bytes_transferred;
        if (out_head->rptr == out_head->wptr) {
            struct connection_buffer *b = out_head;
            out_head = b->next;
            if (!out_head) {
                out_tail = 0;
            }
            delete_connection_buffer(b);
        }
    }

    bytes_to_write -= bytes_transferred;
    if (bytes_to_write > 0) {
        tgl_state::instance()->io_service->post(boost::bind(&connection::start_write, shared_from_this()));
    }
}

void connection::incr_out_packet_num() {
    assert(!destroyed);
    out_packet_num++;
}

std::shared_ptr<tgl_dc> connection::dc() {
    assert(!destroyed);
    return _dc;
}

std::shared_ptr<tgl_session> connection::session() {
    assert(!destroyed);
    return _session;
}

struct tgl_net_methods tgl_asio_net = {
    .write_out = tgln_write_out,
    .read_in = tgln_read_in,
    .flush_out = tgln_flush_out,
    .incr_out_packet_num = incr_out_packet_num,
    .free = tgln_free,
    .get_dc = get_dc,
    .get_session = get_session,
    .create_connection = tgln_create_connection,
};
