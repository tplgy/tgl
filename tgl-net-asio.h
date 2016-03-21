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

struct connection
{
    std::string ip;
    int port;
    int flags;
    enum conn_state state;
    int ipv6[4];
    struct connection_buffer *in_head;
    struct connection_buffer *in_tail;
    struct connection_buffer *out_head;
    struct connection_buffer *out_tail;
    int in_bytes;
    int bytes_to_write;
    int packet_num;
    int out_packet_num;
    int last_connect_time;
    struct mtproto_methods *methods;
    std::shared_ptr<tgl_session> session;
    std::shared_ptr<tgl_dc> dc;
    void *extra;
    double last_receive_time;

    connection(boost::asio::io_service& io_service);
    ~connection();

    bool connect();
    void restart();
    void fail();

    void read();
    void write();
    void flush();

    void start_ping_timer();

private:
    void handle_read(const boost::system::error_code&, size_t);
    void handle_write(const boost::system::error_code&, size_t);

    void stop_ping_timer();
    void ping_alarm(const boost::system::error_code&);

    void start_fail_timer();
    void fail_alarm(const boost::system::error_code&);

    boost::asio::ip::tcp::socket socket;
    boost::asio::deadline_timer ping_timer;
    boost::asio::deadline_timer fail_timer;

    bool in_fail_timer;
    bool write_pending;
};

//extern struct connection *Connections[];

int tgln_write_out (struct connection *c, const void *data, int len);
void tgln_flush_out (struct connection *c);
int tgln_read_in (struct connection *c, void *data, int len);
int tgln_read_in_lookup (struct connection *c, void *data, int len);

//void tgln_insert_msg_id (struct tgl_session *S, long long id);

extern struct tgl_net_methods tgl_asio_net;

#endif
