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
#ifndef __TGL_H__
#define __TGL_H__

#include "crypto/bn.h"
#include "tgl-dc.h"
#include "tgl-layout.h"
#include "tgl-log.h"
#include <map>
#include <memory>
#include <stdlib.h>
#include <string.h>
#include <vector>

//#define ENABLE_SECRET_CHAT

#define TGL_MAX_DC_NUM 100
#define TG_SERVER_1 "149.154.175.50"
#define TG_SERVER_2 "149.154.167.51"
#define TG_SERVER_3 "149.154.175.100"
#define TG_SERVER_4 "149.154.167.91"
#define TG_SERVER_5 "149.154.171.5"
#define TG_SERVER_IPV6_1 "2001:b28:f23d:f001::a"
#define TG_SERVER_IPV6_2 "2001:67c:4e8:f002::a"
#define TG_SERVER_IPV6_3 "2001:b28:f23d:f003::a"
#define TG_SERVER_IPV6_4 "2001:67c:4e8:f004::a"
#define TG_SERVER_IPV6_5 "2001:b28:f23f:f005::a"
#define TG_SERVER_DEFAULT 2

#define TG_SERVER_TEST_1 "149.154.175.10"
#define TG_SERVER_TEST_2 "149.154.167.40"
#define TG_SERVER_TEST_3 "149.154.175.117"
#define TG_SERVER_TEST_IPV6_1 "2001:b28:f23d:f001::e"
#define TG_SERVER_TEST_IPV6_2 "2001:67c:4e8:f002::e"
#define TG_SERVER_TEST_IPV6_3 "2001:b28:f23d:f003::e"
#define TG_SERVER_TEST_DEFAULT 1

#define TGL_VERSION "2.1.0"

#define TGL_ENCRYPTED_LAYER 17
#define TGL_SCHEME_LAYER 45

class tgl_connection;
struct tgl_session;
struct tgl_dc;
struct query;
struct tgl_state;

enum tgl_value_type {
    tgl_phone_number,           // user phone number
    tgl_code,                   // telegram login code, or 'call' for phone call request
    tgl_register_info,          // "Y/n" register?, first name, last name
    tgl_new_password,           // new pass, confirm new pass
    tgl_cur_and_new_password,   // curr pass, new pass, confirm new pass
    tgl_cur_password,           // current pass
    tgl_bot_hash
};

enum tgl_user_update_type {
    tgl_update_firstname = 0,
    tgl_update_last_name,
    tgl_update_username,
    tgl_update_phone,
    tgl_update_blocked
};

enum tgl_user_status_type {
    tgl_user_status_offline,
    tgl_user_status_online,
    tgl_user_status_recently,
    tgl_user_status_last_week,
    tgl_user_status_last_month
};

#define TGL_LOCK_DIFF 1
#define TGL_LOCK_PASSWORD 2
#define TGL_LOCK_PHONE 4

class tgl_download_manager;
class tgl_connection_factory;
class tgl_rsa_key;
class tgl_timer;
class tgl_timer_factory;
class tgl_update_callback;
struct tgl_secret_chat;

struct tgl_state {
  static tgl_state *instance();

  int encr_root;
  unsigned char *encr_prime;
  TGLC_bn *encr_prime_bn;
  int encr_param_version;

  int active_queries;
  int started;

  long long locks;
  std::vector<std::shared_ptr<tgl_dc>> DC_list;
  std::shared_ptr<tgl_dc> DC_working;
  int temp_key_expire_time;

  TGLC_bn_ctx *bn_ctx;

  std::vector<tgl_message*> unsent_messages;

  std::vector<std::shared_ptr<query>> queries_tree;

  std::shared_ptr<tgl_timer> ev_login;

  int init(const std::string &&download_dir, int app_id, const std::string &app_hash, const std::string &app_version);
  void login();

  void set_auth_key(int num, const char *buf);
  void set_our_id(int id);
  void set_dc_option (int flags, int id, std::string ip, int port);
  void set_dc_signed(int num);
  void set_working_dc(int num);
  void set_qts(int qts);
  void set_pts(int pts, bool force = false);
  void set_date(int date, bool force = false);
  void set_seq(int seq);
  void reset_server_state();
  void set_callback(const std::shared_ptr<tgl_update_callback>& cb) { m_callback = cb; }
  void add_rsa_key(const std::string& key);
  void set_enable_pfs (bool); // enable perfect forward secrecy (does not work properly right now)
  void set_test_mode (bool);
  void set_connection_factory(const std::shared_ptr<tgl_connection_factory>& factory) { m_connection_factory = factory; }
  void set_timer_factory(const std::shared_ptr<tgl_timer_factory>& factory) { m_timer_factory = factory; }
  void set_enable_ipv6 (bool val);

  const std::string& app_version() const { return m_app_version; }
  const std::string& app_hash() const { return m_app_hash; }
  int app_id() const { return m_app_id; }
  const std::vector<std::unique_ptr<tgl_rsa_key>>& rsa_key_list() const { return m_rsa_key_list; }

  const std::shared_ptr<tgl_download_manager>& download_manager() const { return m_download_manager; }
  const std::shared_ptr<tgl_connection_factory>& connection_factory() const { return m_connection_factory; }
  const std::shared_ptr<tgl_timer_factory>& timer_factory() const { return m_timer_factory; }
  const std::shared_ptr<tgl_update_callback>& callback() const { return m_callback; }

  void set_error(std::string error, int error_code);

  int pts() { return m_pts; }
  int qts() { return m_qts; }
  int seq() { return m_seq; }
  int date() { return m_date; }
  bool test_mode() { return m_test_mode; }
  tgl_peer_id_t our_id() { return m_our_id; }
  bool ipv6_enabled() { return m_ipv6_enabled; }
  bool pfs_enabled() { return m_enable_pfs; }

  std::shared_ptr<tgl_secret_chat> secret_chat_for_id(const tgl_peer_id_t& id) const
  {
      return secret_chat_for_id(id.peer_id);
  }
  std::shared_ptr<tgl_secret_chat> secret_chat_for_id(int peer_id) const;
  std::shared_ptr<tgl_secret_chat> ensure_secret_chat(const tgl_peer_id_t& id);

private:
  int m_app_id;
  std::string m_app_hash;

  std::string m_error;
  int m_error_code;

  int m_pts;
  int m_qts;
  int m_date;
  int m_seq;
  bool m_test_mode; // Connects to the telegram test servers instead of the regular servers
  tgl_peer_id_t m_our_id; // ID of logged in user
  bool m_enable_pfs;
  std::string m_app_version;
  bool m_ipv6_enabled;
  std::vector<std::unique_ptr<tgl_rsa_key>> m_rsa_key_list;
  std::map<int/*peer id*/, std::shared_ptr<tgl_secret_chat>> m_secret_chats;

  tgl_state();

  std::shared_ptr<tgl_download_manager> m_download_manager;
  std::shared_ptr<tgl_timer_factory> m_timer_factory;
  std::shared_ptr<tgl_connection_factory> m_connection_factory;
  std::shared_ptr<tgl_update_callback> m_callback;
};

int tgl_secret_chat_for_user (tgl_peer_id_t user_id);
int tgl_do_send_bot_auth (const char *code, int code_len, void (*callback)(std::shared_ptr<void> callback_extra, bool success, struct tgl_user *Self), std::shared_ptr<void> callback_extra);

#define TGL_PEER_USER 1
#define TGL_PEER_CHAT 2
#define TGL_PEER_GEO_CHAT 3
#define TGL_PEER_ENCR_CHAT 4
#define TGL_PEER_CHANNEL 5
#define TGL_PEER_TEMP_ID 100
#define TGL_PEER_RANDOM_ID 101
#define TGL_PEER_UNKNOWN 0

#define TGL_MK_USER(id) tgl_set_peer_id (TGL_PEER_USER,id)
#define TGL_MK_CHAT(id) tgl_set_peer_id (TGL_PEER_CHAT,id)
#define TGL_MK_CHANNEL(id) tgl_set_peer_id (TGL_PEER_CHANNEL,id)
#define TGL_MK_GEO_CHAT(id) tgl_set_peer_id (TGL_PEER_GEO_CHAT,id)
#define TGL_MK_ENCR_CHAT(id) tgl_set_peer_id (TGL_PEER_ENCR_CHAT,id)

static inline int tgl_get_peer_type (const tgl_peer_id_t& id) {
  return id.peer_type;
}

static inline int tgl_get_peer_id (const tgl_peer_id_t& id) {
  return id.peer_id;
}

static inline tgl_peer_id_t tgl_set_peer_id (int type, int id) {
  tgl_peer_id_t ID;
  ID.peer_id = id;
  ID.peer_type = type;
  ID.access_hash = 0;
  return ID;
}

static inline int tgl_cmp_peer_id (tgl_peer_id_t a, tgl_peer_id_t b) {
  return memcmp (&a, &b, 8);
}

int tgl_authorized_dc(const std::shared_ptr<tgl_dc>& DC);
int tgl_signed_dc(const std::shared_ptr<tgl_dc>& DC);

void tgl_dc_authorize (const std::shared_ptr<tgl_dc>& DC);

#define TGL_SEND_MSG_FLAG_DISABLE_PREVIEW 1
#define TGL_SEND_MSG_FLAG_ENABLE_PREVIEW 2

#define TGL_SEND_MSG_FLAG_DOCUMENT_IMAGE TGLDF_IMAGE
#define TGL_SEND_MSG_FLAG_DOCUMENT_STICKER TGLDF_STICKER
#define TGL_SEND_MSG_FLAG_DOCUMENT_ANIMATED TGLDF_ANIMATED
#define TGL_SEND_MSG_FLAG_DOCUMENT_AUDIO TGLDF_AUDIO
#define TGL_SEND_MSG_FLAG_DOCUMENT_VIDEO TGLDF_VIDEO
#define TGL_SEND_MSG_FLAG_DOCUMENT_AUTO 32
#define TGL_SEND_MSG_FLAG_DOCUMENT_PHOTO 64

#define TGL_SEND_MSG_FLAG_REPLY(x) (((unsigned long long)x) << 32)

typedef int tgl_user_id_t;
typedef int tgl_chat_id_t;
typedef int tgl_secret_chat_id_t;
typedef int tgl_user_or_chat_id_t;

void tgl_do_lookup_state ();

#endif
