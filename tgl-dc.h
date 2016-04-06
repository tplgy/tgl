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

#define MAX_DC_SESSIONS 3

struct tgl_dc;
class tgl_connection;
class tgl_timer;

struct tgl_session {
  std::weak_ptr<tgl_dc> dc;
  long long session_id = 0;
  long long last_msg_id = 0;
  int seq_no = 0;
  int received_messages = 0;
  std::shared_ptr<tgl_connection> c = nullptr;
  std::vector<long> ack_tree;
  std::shared_ptr<tgl_timer> ev = nullptr;
};

struct tgl_dc_option {
    std::vector<std::pair<std::string, int>> option_list;
};

struct tgl_dc {
    int id;
    int flags = 0;
    int rsa_key_idx = 0;
    enum tgl_dc_state state = st_init;
    std::array<std::shared_ptr<tgl_session>, MAX_DC_SESSIONS> sessions;
    unsigned char auth_key[256];
    unsigned char temp_auth_key[256];
    unsigned char nonce[256];
    unsigned char new_nonce[256];
    unsigned char server_nonce[256];
    long long auth_key_id = 0;
    long long temp_auth_key_id = 0;
    long long temp_auth_key_bind_query_id = 0;

    long long server_salt = 0;
    std::shared_ptr<tgl_timer> ev = nullptr;

    int server_time_delta = 0;
    double server_time_udelta = 0;

    // ipv4, ipv6, ipv4_media, ipv6_media
    std::array<tgl_dc_option, 4> options;

    void add_query(std::shared_ptr<struct query> q);
    void remove_query(std::shared_ptr<struct query> q);

    void add_pending_query(std::shared_ptr<struct query> q);
    void remove_pending_query(std::shared_ptr<struct query> q);
    void send_pending_queries();

private:
    std::list<std::shared_ptr<struct query>> active_queries;
    std::list<std::shared_ptr<struct query>> pending_queries;
};

#pragma pack(pop)
#endif
