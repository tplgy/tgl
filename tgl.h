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
*/
#ifndef __TGL_H__
#define __TGL_H__

#include "crypto/bn.h"
#include "tgl-layout.h"
#include <string.h>
#include <string>
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

struct connection;
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
          void (*callback)(struct tgl_state *TLS, const void *answer, const void *arg), const void *arg);
  void (*logged_in)();
  void (*started)();
  void (*type_notification)(int user_id, enum tgl_typing_status status);
  void (*type_in_chat_notification)(int user_id, int chat_id, enum tgl_typing_status status);
  void (*type_in_secret_chat_notification)(int chat_id);
  void (*status_notification)(int user_id, enum tgl_user_status_type, int expires);
  void (*user_registered)(int user_id);
  void (*new_authorization)(const char *device, const char *location);
  void (*new_user)(int user_id, const char *phone, const char *fistname, const char *lastname, const char *username);
  void (*user_update)(int user_id, void *value, enum tgl_user_update_type update_type);
  void (*user_deleted)(int id);
  void (*profile_picture_update)(int peer_id, long long int photo_id, struct tgl_file_location *photo_small, struct tgl_file_location *photo_big);
  void (*chat_update)(int chat_id, int peers_num, int admin, struct tgl_photo *photo, int date, const char *title, int tl);
  void (*chat_add_user)(int chat_id, int user, int inviter, int date);
  void (*chat_delete_user)(int chat_id, int user);
  void (*secret_chat_update)(struct tgl_secret_chat *C, unsigned flags);
  void (*channel_update)(struct tgl_channel *C, unsigned flags);
  void (*msg_receive)(struct tgl_message *M);
  void (*our_id)(int id);
  void (*notification)(const char *type, const char *message);
  void (*dc_update)(struct tgl_dc *);
  void (*change_active_dc)(int new_dc_id);
  char *(*create_print_name) (tgl_peer_id_t id, const char *a1, const char *a2, const char *a3, const char *a4);
  void (*on_failed_login) ();
};

struct tgl_net_methods {
  int (*write_out) (struct connection *c, const void *data, int len);
  int (*read_in) (struct connection *c, void *data, int len);
  void (*flush_out) (struct connection *c);
  void (*incr_out_packet_num) (struct connection *c);
  void (*free) (struct connection *c);
  struct tgl_dc *(*get_dc) (struct connection *c);
  struct tgl_session *(*get_session) (struct connection *c);

  struct connection *(*create_connection) (struct tgl_state *TLS, const char *host, int port, struct tgl_session *session, struct tgl_dc *dc, struct mtproto_methods *methods);
};

struct mtproto_methods {
  int (*ready) (struct tgl_state *TLS, struct connection *c);
  int (*close) (struct tgl_state *TLS, struct connection *c);
  int (*execute) (struct tgl_state *TLS, struct connection *c, int op, int len);
};

struct tgl_timer;
struct tree_random_id;
struct tree_temp_id;

struct tgl_timer_methods {
  struct tgl_timer *(*alloc) (struct tgl_state *TLS, void (*cb)(struct tgl_state *TLS, void *arg), void *arg);
  void (*insert) (struct tgl_timer *t, double timeout);
  void (*remove) (struct tgl_timer *t);
  void (*free) (struct tgl_timer *t);
};

#define E_ERROR 0
#define E_WARNING 1
#define E_NOTICE 2
#define E_DEBUG2 3
#define E_DEBUG 6

#define TGL_LOCK_DIFF 1
#define TGL_LOCK_PASSWORD 2

#define TGL_MAX_RSA_KEYS_NUM 10
// Do not modify this structure, unless you know what you do

struct event_base;

#pragma pack(push,4)
struct tgl_state {
  tgl_peer_id_t our_id;
  int encr_root;
  unsigned char *encr_prime;
  TGLC_bn *encr_prime_bn;
  int encr_param_version;
  int pts;
  int qts;
  int date;
  int seq;
  int test_mode; // Connects to the telegram test servers instead of the regular servers
  int verbosity;
  int active_queries;
  int max_msg_id;
  int started;

  long long locks;
  struct tgl_dc *DC_list[TGL_MAX_DC_NUM];
  struct tgl_dc *DC_working;
  int max_dc_num;
  int dc_working_num;
  int enable_pfs;
  int temp_key_expire_time;

  long long cur_uploading_bytes;
  long long cur_uploaded_bytes;
  long long cur_downloading_bytes;
  long long cur_downloaded_bytes;

  char *downloads_directory;

  struct tgl_update_callback callback;
  struct tgl_net_methods *net_methods;
  struct event_base *ev_base;

  char *rsa_key_list[TGL_MAX_RSA_KEYS_NUM];
  // (TGLC_rsa *)
  void *rsa_key_loaded[TGL_MAX_RSA_KEYS_NUM];
  long long rsa_key_fingerprint[TGL_MAX_RSA_KEYS_NUM];
  int rsa_key_num;

  TGLC_bn_ctx *TGLC_bn_ctx;

  std::vector<tgl_message*> unsent_messages;

  struct tgl_timer_methods *timer_methods;

  std::vector<query*> queries_tree;

  int app_id;
  char *app_hash;

  void *ev_login;

  char *app_version;
  int ipv6_enabled;

  struct tree_random_id *random_id_tree;
  struct tree_temp_id *temp_id_tree;

  char *error;
  int error_code;

  int is_bot;

  int last_temp_id;
};
#pragma pack(pop)

//extern struct tgl_state tgl_state;

tgl_peer_t *tgl_peer_get (struct tgl_state *TLS, tgl_peer_id_t id);

struct tgl_message *tgl_message_get (struct tgl_state *TLS, tgl_message_id_t *id);
void tgl_peer_iterator_ex (struct tgl_state *TLS, void (*it)(tgl_peer_t *P, void *extra), void *extra);

int tgl_complete_user_list (struct tgl_state *TLS, int index, const char *text, int len, char **R);
int tgl_complete_chat_list (struct tgl_state *TLS, int index, const char *text, int len, char **R);
int tgl_complete_encr_chat_list (struct tgl_state *TLS, int index, const char *text, int len, char **R);
int tgl_complete_peer_list (struct tgl_state *TLS, int index, const char *text, int len, char **R);
int tgl_complete_channel_list (struct tgl_state *TLS, int index, const char *text, int len, char **R);
int tgl_secret_chat_for_user (struct tgl_state *TLS, tgl_peer_id_t user_id);
int tgl_do_send_bot_auth (struct tgl_state *TLS, const char *code, int code_len, void (*callback)(struct tgl_state *TLS, void *callback_extra, int success, struct tgl_user *Self), void *callback_extra);

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

void tgl_set_auth_key(struct tgl_state *TLS, int num, const char *buf);
void tgl_set_our_id(struct tgl_state *TLS, int id);
void tgl_set_dc_option (struct tgl_state *TLS, int flags, int id, const char *ip, int l2, int port);
void tgl_set_dc_signed(struct tgl_state *TLS, int num);
void tgl_set_working_dc(struct tgl_state *TLS, int num);
void tgl_set_qts(struct tgl_state *TLS, int qts);
void tgl_set_pts(struct tgl_state *TLS, int pts);
void tgl_set_date(struct tgl_state *TLS, int date);
void tgl_set_seq(struct tgl_state *TLS, int seq);
void tgl_set_auth_file_path (struct tgl_state *TLS, const char *path);
void tgl_set_download_directory (struct tgl_state *TLS, const char *path);
void tgl_set_callback (struct tgl_state *TLS, struct tgl_update_callback *cb);
void tgl_set_rsa_key (struct tgl_state *TLS, const char *key);
void tgl_set_rsa_key_direct (struct tgl_state *TLS, unsigned long e, int n_bytes, const unsigned char *n);
void tgl_set_app_version (struct tgl_state *TLS, const char *app_version);

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

static inline int tgl_cmp_peer_id (tgl_peer_id_t a, tgl_peer_id_t b) {
  return memcmp (&a, &b, 8);
}

void tgl_incr_verbosity (struct tgl_state *TLS);
void tgl_set_verbosity (struct tgl_state *TLS, int val);
void tgl_enable_pfs (struct tgl_state *TLS);
void tgl_set_test_mode (struct tgl_state *TLS);
void tgl_set_net_methods (struct tgl_state *TLS, struct tgl_net_methods *methods);
void tgl_set_timer_methods (struct tgl_state *TLS, struct tgl_timer_methods *methods);
void tgl_set_ev_base (struct tgl_state *TLS, void *ev_base);

int tgl_authorized_dc(struct tgl_dc *DC);
int tgl_signed_dc(struct tgl_dc *DC);

int tgl_init (struct tgl_state *TLS);
void tgl_dc_authorize (struct tgl_state *TLS, struct tgl_dc *DC);

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

void tgl_register_app_id (struct tgl_state *TLS, int app_id, const char *app_hash);

void tgl_login (struct tgl_state *TLS);
void tgl_enable_ipv6 (struct tgl_state *TLS);
void tgl_enable_bot (struct tgl_state *TLS);

struct tgl_state *tgl_state_alloc (void);

void tgl_do_lookup_state (struct tgl_state *TLS);

long long tgl_get_allocated_bytes (void);

#endif
