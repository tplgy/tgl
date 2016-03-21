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

#include <boost/asio.hpp>

struct connection_buffer {
    unsigned char *start;
    unsigned char *end;
    unsigned char *rptr;
    unsigned char *wptr;
    struct connection_buffer *next;
};

enum conn_state {
    conn_none,
    conn_connecting,
    conn_ready,
    conn_failed,
    conn_stopped
};

struct tgl_dc;
struct tgl_session;
struct connection;

class asio_connection : public std::enable_shared_from_this<asio_connection>
{
public:
    asio_connection(std::shared_ptr<connection> c, boost::asio::io_service& io_service, const std::string& host, int port,
            std::shared_ptr<tgl_session> session, std::shared_ptr<tgl_dc> dc, struct mtproto_methods *methods);
    ~asio_connection();

    bool connect();
    void restart();
    void fail();

    int read(void *buffer, int len);
    int write(const void *data, int len);
    void flush();

    void start_ping_timer();

    void incr_out_packet_num();
    std::shared_ptr<tgl_dc> dc();
    std::shared_ptr<tgl_session> session();

private:
    void start_read();
    void handle_read(const boost::system::error_code&, size_t);

    void start_write();
    void handle_write(const boost::system::error_code&, size_t);

    void stop_ping_timer();
    void ping_alarm(const boost::system::error_code&);

    void start_fail_timer();
    void fail_alarm(const boost::system::error_code&);

    int read_in_lookup(void *data, int len);
    void try_rpc_read();

    std::weak_ptr<connection> c;

    std::string ip;
    int port;
    enum conn_state state;
    boost::asio::ip::tcp::socket socket;
    boost::asio::deadline_timer ping_timer;
    boost::asio::deadline_timer fail_timer;

    int out_packet_num;
    struct connection_buffer *in_head;
    struct connection_buffer *in_tail;
    struct connection_buffer *out_head;
    struct connection_buffer *out_tail;
    int in_bytes;
    int bytes_to_write;
    std::shared_ptr<tgl_dc> _dc;
    struct mtproto_methods *methods;
    std::shared_ptr<tgl_session> _session;

    int last_connect_time;
    double last_receive_time;

    bool in_fail_timer;
    bool write_pending;
};

struct connection : public std::enable_shared_from_this<struct connection>
{
    connection(boost::asio::io_service& io_service, const std::string& host, int port,
            std::shared_ptr<tgl_session> session, std::shared_ptr<tgl_dc> dc,
            struct mtproto_methods *methods);

    void free();

    bool connect();
    void restart();
    void fail();

    int read(void *buffer, int len);
    int write(const void *data, int len);
    void flush();

    void start_ping_timer();

    void incr_out_packet_num();

    std::shared_ptr<tgl_dc> dc();
    std::shared_ptr<tgl_session> session();

    std::shared_ptr<asio_connection> impl();

private:
    std::shared_ptr<asio_connection> asio;

    boost::asio::io_service& io_service;
    const std::string& host;
    int port;
    std::shared_ptr<tgl_session> _session;
    std::shared_ptr<tgl_dc> _dc;
    struct mtproto_methods *methods;
};

int tgln_write_out(std::shared_ptr<connection> c, const void *data, int len);
void tgln_flush_out(std::shared_ptr<connection> c);
int tgln_read_in(std::shared_ptr<connection> c, void *data, int len);
int tgln_read_in_lookup(std::shared_ptr<connection> c, void *data, int len);

//void tgln_insert_msg_id (struct tgl_session *S, long long id);

extern struct tgl_net_methods tgl_asio_net;

#endif
