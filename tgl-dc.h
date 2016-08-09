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

    Copyright Vitaly Valtman 2014-2015
    Copyright Topology LP 2016
*/
#ifndef __TGL_DC_H__
#define __TGL_DC_H__

#include <array>
#include <list>
#include <memory>
#include <set>
#include <string>
#include <vector>
#include "types/tgl_peer_id.h"

#pragma pack(push,4)

enum tgl_dc_state {
  st_init,
  st_reqpq_sent,
  st_reqdh_sent,
  st_client_dh_sent,
  st_init_temp,
  st_reqpq_sent_temp,
  st_reqdh_sent_temp,
  st_client_dh_sent_temp,
  st_authorized,
  st_error
};

#define TGLDCF_AUTHORIZED 1
#define TGLDCF_BOUND 2
#define TGLDCF_CONFIGURED 4
#define TGLDCF_LOGGED_IN 8

struct tgl_dc;
class tgl_connection;
class tgl_timer;
class query;

struct tgl_session {
    std::weak_ptr<tgl_dc> dc;
    int64_t session_id;
    int64_t last_msg_id;
    int32_t seq_no;
    int32_t received_messages;
    std::shared_ptr<tgl_connection> c;
    std::set<int64_t> ack_set;
    std::shared_ptr<tgl_timer> ev;
    tgl_session()
        : dc()
        , session_id(0)
        , last_msg_id(0)
        , seq_no(0)
        , received_messages(0)
        , c()
        , ack_set()
        , ev()
    { }

    void clear();
};

struct tgl_dc_option {
    std::vector<std::pair<std::string, int>> option_list;
};

struct tgl_dc {
    tgl_dc();

    void reset();

    int32_t id;
    int flags;
    int rsa_key_idx;
    enum tgl_dc_state state;
    std::shared_ptr<tgl_session> session;
    unsigned char auth_key[256];
    unsigned char temp_auth_key[256];
    unsigned char nonce[256];
    unsigned char new_nonce[256];
    unsigned char server_nonce[256];
    int64_t auth_key_id;
    int64_t temp_auth_key_id;
    int64_t temp_auth_key_bind_query_id;

    int64_t server_salt;
    std::shared_ptr<tgl_timer> ev;

    int server_time_delta;
    double server_time_udelta;

    bool auth_transfer_in_process;

//    // ipv4, ipv6, ipv4_media, ipv6_media
//    std::array<tgl_dc_option, 4> options;
    tgl_dc_option ipv6_options;
    tgl_dc_option ipv4_options;

    void increase_active_queries(size_t num = 1);
    void decrease_active_queries(size_t num = 1);

    void add_pending_query(const std::shared_ptr<query>& q);
    void remove_pending_query(const std::shared_ptr<query>& q);
    void send_pending_queries();

private:
    size_t m_active_queries;
    std::list<std::shared_ptr<query>> m_pending_queries;

    void cleanup_timer_expired();
    std::shared_ptr<tgl_timer> m_session_cleanup_timer;
};

#pragma pack(pop)
#endif
