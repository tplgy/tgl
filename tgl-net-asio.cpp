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
        tgl_do_send_ping(this);
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
    ping_timer.async_wait(boost::bind(&connection::ping_alarm, this, boost::asio::placeholders::error));
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
    fail_timer.async_wait(boost::bind(&connection::fail_alarm, this, boost::asio::placeholders::error));
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

int tgln_write_out(struct connection *c, const void *_data, int len) {
    TGL_DEBUG("write_out: " << len << " bytes\n");
    const unsigned char *data = (const unsigned char *)_data;
    if (!len) { return 0; }
    assert (len > 0);
    int x = 0;
    if (!c->out_head) {
        struct connection_buffer *b = new_connection_buffer(1 << 20);
        c->out_head = c->out_tail = b;
    }
    while (len) {
        if (c->out_tail->end - c->out_tail->wptr >= len) {
            memcpy(c->out_tail->wptr, data, len);
            c->out_tail->wptr += len;
            c->bytes_to_write += len;
            x += len;
            break;
        } else {
            int y = c->out_tail->end - c->out_tail->wptr;
            assert(y < len);
            memcpy(c->out_tail->wptr, data, y);
            x += y;
            len -= y;
            data += y;
            struct connection_buffer *b = new_connection_buffer (1 << 20);
            c->out_tail->next = b;
            b->next = 0;
            c->out_tail = b;
            c->bytes_to_write += y;
        }
    }
    if (c->bytes_to_write) {
        tgl_state::instance()->io_service->post(boost::bind(&connection::write, c));
    }
    return x;
}

int tgln_read_in(struct connection *c, void *_data, int len) {
    unsigned char *data = (unsigned char *)_data;
    if (!len) { return 0; }
    assert (len > 0);
    if (len > c->in_bytes) {
        len = c->in_bytes;
    }
    int x = 0;
    while (len) {
        int y = c->in_head->wptr - c->in_head->rptr;
        if (y > len) {
            memcpy (data, c->in_head->rptr, len);
            c->in_head->rptr += len;
            c->in_bytes -= len;
            return x + len;
        } else {
            memcpy(data, c->in_head->rptr, y);
            c->in_bytes -= y;
            x += y;
            data += y;
            len -= y;
            struct connection_buffer *old = c->in_head;
            c->in_head = c->in_head->next;
            if (!c->in_head) {
                c->in_tail = 0;
            }
            delete_connection_buffer(old);
        }
    }
    return x;
}

int tgln_read_in_lookup(struct connection *c, void *_data, int len) {
    unsigned char *data = (unsigned char *)_data;
    if (!len || !c->in_bytes) { return 0; }
    assert (len > 0);
    if (len > c->in_bytes) {
        len = c->in_bytes;
    }
    int x = 0;
    struct connection_buffer *b = c->in_head;
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

void tgln_flush_out(struct connection *c) {
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

struct connection *tgln_create_connection(const std::string &host, int port, std::shared_ptr<tgl_session> session, std::shared_ptr<tgl_dc> dc, struct mtproto_methods *methods) {
    struct connection* c = new connection(*tgl_state::instance()->io_service);
    c->ip = host;
    c->port = port;

    if (!c->connect()) {
        TGL_ERROR("Can not connect to " << host << ":" << port << "\n");
        delete c;
        return 0;
    }

    c->state = conn_connecting;
    c->last_receive_time = tglt_get_double_time();
    c->flags = 0;

    c->dc = dc;
    c->session = session;
    c->methods = methods;

    c->start_ping_timer();
    c->read();

    char byte = 0xef; // use abridged protocol
    assert(tgln_write_out(c, &byte, 1) == 1);
    tgln_flush_out(c);

    return c;
}

void connection::restart() {
    if (last_connect_time == time(0)) {
        start_fail_timer();
        return;
    }

    last_connect_time = time(0);
    if (!connect()) {
        TGL_WARNING("Can not reconnect to " << ip << ":" << port << "\n");
        start_fail_timer();
        return;
    }

    TGL_DEBUG("restarting connection to " << ip << ":" << port << "\n");

    state = conn_connecting;
    last_receive_time = tglt_get_double_time();
    start_ping_timer();
    read();

    char byte = 0xef; // use abridged protocol
    assert(tgln_write_out(this, &byte, 1) == 1);
    tgln_flush_out(this);
}

void connection::fail() {
    if (state == conn_ready || state == conn_connecting) {
        stop_ping_timer();
    }
    socket.close();

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

static void try_rpc_read(struct connection *c) {
    assert (c->in_head);

    while (1) {
        if (c->in_bytes < 1) { return; }
        unsigned len = 0;
        unsigned t = 0;
        assert(tgln_read_in_lookup(c, &len, 1) == 1);
        if (len >= 1 && len <= 0x7e) {
            if (c->in_bytes < (int)(1 + 4 * len)) { return; }
        } else {
            if (c->in_bytes < 4) { return; }
            assert(tgln_read_in_lookup(c, &len, 4) == 4);
            len = (len >> 8);
            if (c->in_bytes < (int)(4 + 4 * len)) { return; }
            len = 0x7f;
        }

        if (len >= 1 && len <= 0x7e) {
            assert(tgln_read_in (c, &t, 1) == 1);
            assert(t == len);
            assert(len >= 1);
        } else {
            assert(len == 0x7f);
            assert(tgln_read_in(c, &len, 4) == 4);
            len = (len >> 8);
            assert(len >= 1);
        }
        len *= 4;
        int op;
        assert(tgln_read_in_lookup(c, &op, 4) == 4);
        if (c->methods->execute(c, op, len) < 0) {
            c->fail();
            return;
        }
    }
}

static void incr_out_packet_num(struct connection *c) {
    c->out_packet_num++;
}

static std::shared_ptr<tgl_dc> get_dc(struct connection *c) {
    return c->dc;
}

static std::shared_ptr<tgl_session> get_session(struct connection *c) {
    return c->session;
}

static void tgln_free(struct connection *c) {
    delete c;
}

connection::connection(boost::asio::io_service& io_service)
    : port(0)
    , flags(0)
    , state(conn_none)
    , ipv6{0, 0, 0, 0}
    , in_head(nullptr)
    , in_tail(nullptr)
    , out_head(nullptr)
    , out_tail(nullptr)
    , in_bytes(0)
    , bytes_to_write(0)
    , packet_num(0)
    , out_packet_num(0)
    , last_connect_time(0)
    , methods(nullptr)
    , session(nullptr)
    , dc(nullptr)
    , extra(nullptr)
    , last_receive_time(0)
    , socket(io_service)
    , ping_timer(io_service)
    , fail_timer(io_service)
    , in_fail_timer(false)
    , write_pending(false)
{
}

connection::~connection()
{
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
        TGL_WARNING("error connection to " << endpoint << ": " << ec.message() << "\n");
        return false;
    }
    TGL_NOTICE("connected to " << endpoint << "\n");
    return true;
}

void connection::read() {
    if (!in_tail) {
        in_head = in_tail = new_connection_buffer(1 << 20);
    }

    socket.async_receive(boost::asio::buffer(in_tail->wptr, in_tail->end - in_tail->wptr),
            boost::bind(&connection::handle_read, this,
                boost::asio::placeholders::error,
                boost::asio::placeholders::bytes_transferred));
}

void connection::write() {
    if (state == conn_connecting) {
        state = conn_ready;
        methods->ready(this);
    }

    if (!write_pending && bytes_to_write > 0) {
        write_pending = true;
        assert(out_head);
        socket.async_send(boost::asio::buffer(out_head->rptr, out_head->wptr - out_head->rptr),
                boost::bind(&connection::handle_write, this,
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred));
    }
}

void connection::flush() {
}

void connection::handle_read(const boost::system::error_code& ec, size_t bytes_transferred) {
    if (ec) {
        if (ec != boost::asio::error::operation_aborted) {
            TGL_WARNING("read error: " << ec << " (" << ec.message() << ")" << std::endl);
            fail();
        }
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
        try_rpc_read(this);
    }

    read();
}

void connection::handle_write(const boost::system::error_code& ec, size_t bytes_transferred) {
    write_pending = false;
    if (ec) {
        TGL_WARNING("write error: " << ec << " (" << ec.message() << ")" << std::endl);
        fail();
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
        tgl_state::instance()->io_service->post(boost::bind(&connection::write, this));
    }
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
