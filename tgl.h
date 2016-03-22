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
#include "tgl-layout.h"
#include "tgl-log.h"
#include <memory>
#include <stdlib.h>
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

class connection;
struct mtproto_methods;
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

struct tgl_update_callback {
  void (*new_msg)(struct tgl_message *M);
  void (*msg_sent)(long long int old_msg_id, long long int new_msg_id, int chat_id);
  void (*msg_deleted)(long long int msg_id);
  void (*marked_read)(int num, struct tgl_message *list[]);
  //void (*logprintf)(const char *format, ...)  __attribute__ ((format (printf, 1, 2)));
  void (*log_output)(int verbosity, const std::string &str);
  void (*get_values)(enum tgl_value_type type, const char *prompt, int num_values,
          void (*callback)(const void *answer, std::shared_ptr<void> arg), std::shared_ptr<void> arg);
  void (*logged_in)();
  void (*started)();
  void (*type_notification)(int user_id, enum tgl_typing_status status);
  void (*type_in_chat_notification)(int user_id, int chat_id, enum tgl_typing_status status);
  void (*type_in_secret_chat_notification)(int chat_id);
  void (*status_notification)(int user_id, enum tgl_user_status_type, int expires);
  void (*user_registered)(int user_id);
  void (*new_authorization)(const char *device, const char *location);
  void (*new_user)(int user_id, const std::string &phone, const std::string &fistname,
                   const std::string &lastname, const std::string &username);
  void (*user_update)(int user_id, void *value, enum tgl_user_update_type update_type);
  void (*user_deleted)(int id);
  void (*avatar_update)(int peer_id, const tgl_file_location &photo_small, const tgl_file_location &photo_big);
  void (*chat_update)(int chat_id, int peers_num, int admin, int date, const std::string &title);
  void (*chat_add_user)(int chat_id, int user, int inviter, int date);
  void (*chat_delete_user)(int chat_id, int user);
  void (*secret_chat_update)(struct tgl_secret_chat *C, unsigned flags);
  void (*channel_update)(struct tgl_channel *C, unsigned flags);
  void (*msg_receive)(struct tgl_message *M);
  void (*our_id)(int id);
  void (*notification)(const char *type, const char *message);
  void (*dc_update)(std::shared_ptr<tgl_dc>);
  void (*change_active_dc)(int new_dc_id);
  char *(*create_print_name) (tgl_peer_id_t id, const char *a1, const char *a2, const char *a3, const char *a4);
  void (*on_failed_login) ();
};

struct tgl_net_methods {
  int (*write_out) (std::shared_ptr<connection> c, const void *data, int len);
  int (*read_in) (std::shared_ptr<connection> c, void *data, int len);
  void (*flush_out) (std::shared_ptr<connection> c);
  void (*incr_out_packet_num) (std::shared_ptr<connection> c);
  void (*free) (std::shared_ptr<connection> c);
  std::shared_ptr<tgl_dc> (*get_dc) (std::shared_ptr<connection> c);
  std::shared_ptr<tgl_session> (*get_session) (std::shared_ptr<connection> c);

  std::shared_ptr<connection> (*create_connection) (const std::string &host, int port, std::shared_ptr<tgl_session> session, std::shared_ptr<tgl_dc> dc, struct mtproto_methods *methods);
};

struct mtproto_methods {
  int (*ready) (std::shared_ptr<connection> c);
  int (*close) (std::shared_ptr<connection> c);
  int (*execute) (std::shared_ptr<connection> c, int op, int len);
};

struct tgl_timer;

struct tgl_timer_methods {
  struct tgl_timer *(*alloc) (void (*cb)(std::shared_ptr<void> arg), std::shared_ptr<void> arg);
  void (*insert) (struct tgl_timer *t, double timeout);
  void (*remove) (struct tgl_timer *t);
  void (*free) (struct tgl_timer *t);
};

#define TGL_LOCK_DIFF 1
#define TGL_LOCK_PASSWORD 2

namespace boost {
namespace asio {
  class io_service;
}
}

class tgl_download_manager;

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

  struct tgl_update_callback callback;
  struct tgl_net_methods *net_methods;
  boost::asio::io_service *io_service;

  std::vector<char*> rsa_key_list;
  std::vector<void*> rsa_key_loaded;
  std::vector<long long> rsa_key_fingerprint;

  TGLC_bn_ctx *TGLC_bn_ctx;

  std::vector<tgl_message*> unsent_messages;

  struct tgl_timer_methods *timer_methods;

  std::vector<std::shared_ptr<query>> queries_tree;

  void *ev_login;

  void init(const std::string &&download_dir, int app_id, const std::string &app_hash, const std::string &app_version);
  void login();

<<<<<<< ef1fca1d7d40082ef56c3e7896b203c35057a962
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
  void set_callback (struct tgl_update_callback *cb);
  void set_rsa_key (const char *key);
  void set_enable_pfs (bool); // enable perfect forward secrecy (does not work properly right now)
  void set_test_mode (bool);
  void set_net_methods (struct tgl_net_methods *methods);
  void set_timer_methods (struct tgl_timer_methods *methods);
  void set_io_service (boost::asio::io_service* io_service);
  void set_enable_ipv6 (bool val);
  std::string app_version() { return m_app_version; }
  std::string app_hash() { return m_app_hash; }
  int app_id() { return m_app_id; }
  std::shared_ptr<tgl_download_manager> download_manager() { return m_download_manager; }

  void set_error(std::string error, int error_code);

  int pts() { return m_pts; }
  int qts() { return m_qts; }
  int seq() { return m_seq; }
  int date() { return m_date; }
  bool test_mode() { return m_test_mode; }
  int our_id() { return m_our_id; }
  bool ipv6_enabled() { return m_ipv6_enabled; }
  bool pfs_enabled() { return m_enable_pfs; }
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
  int m_our_id; // ID of logged in user
  bool m_enable_pfs;
  std::string m_app_version;
  bool m_ipv6_enabled;

  tgl_state();
  std::shared_ptr<tgl_download_manager> m_download_manager;
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

static inline int tgl_get_peer_type (tgl_peer_id_t id) {
  return id.peer_type;
}

static inline int tgl_get_peer_id (tgl_peer_id_t id) {
  return id.peer_id;
}

static inline tgl_peer_id_t tgl_set_peer_id (int type, int id) {
  tgl_peer_id_t ID;
  ID.peer_id = id;
  ID.peer_type = type;
  ID.access_hash = 0;
  return ID;
}

int tgl_authorized_dc(std::shared_ptr<tgl_dc> DC);
int tgl_signed_dc(std::shared_ptr<tgl_dc> DC);

void tgl_dc_authorize (std::shared_ptr<tgl_dc> DC);

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
