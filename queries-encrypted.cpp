
// This file will be included

#ifdef ENABLE_SECRET_CHAT
#include "queries-encrypted.h"
#include "tgl-layout.h"

#define _FILE_OFFSET_BITS 64
#include <errno.h>
#include <string.h>
#include <memory.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifndef WIN32
#include <sys/utsname.h>
#endif

#include <algorithm>
#include <array>

#include "auto.h"
#include "auto/auto-fetch-ds.h"
#include "auto/auto-free-ds.h"
#include "auto/auto-skip.h"
#include "auto/auto-types.h"
#include "auto/constants.h"
#include "crypto/aes.h"
#include "crypto/md5.h"
#include "mtproto-client.h"
#include "mtproto-common.h"
#include "mtproto-utils.h"
#include "queries.h"
#include "tgl.h"
#include "tgl_download_manager.h"
#include "tgl-log.h"
#include "tgl-methods-in.h"
#include "tg-mime-types.h"
#include "types/tgl_update_callback.h"

struct secret_msg_callback_extra
{
    secret_msg_callback_extra(const std::shared_ptr<tgl_message>& M, int out_seq_no)
        : message(M)
        , out_seq_no(out_seq_no)
    { }
    std::shared_ptr<tgl_message> message;
    int out_seq_no;
};

static void encrypt_decrypted_message(const std::shared_ptr<tgl_secret_chat>& secret_chat,
        const unsigned char msg_sha[20], const int32_t* encr_ptr, const int32_t* encr_end, char* encrypted_data);

/* {{{ Encrypt decrypted */
class secret_chat_encryptor
{
public:
    secret_chat_encryptor(const std::shared_ptr<tgl_secret_chat>& secret_chat,
            const std::shared_ptr<mtprotocol_serializer>& serializer)
        : m_secret_chat(secret_chat)
        , m_serializer(serializer)
    { }

    void start()
    {
        m_encr_base = m_serializer->reserve_i32s(1/*str len*/ + 2/*fingerprint*/ + 4/*msg_key*/ + 1/*len*/);
    }

    void end()
    {
        size_t length = m_serializer->i32_size() - (m_encr_base + 8);
        while ((m_serializer->i32_size() - m_encr_base - 3) & 3) {
            int32_t i;
            tglt_secure_random (reinterpret_cast<unsigned char*>(&i), 4);
            m_serializer->out_i32(i);
        }

        m_serializer->out_i32_at(m_encr_base, (m_serializer->i32_size() - m_encr_base - 1) * 4 * 256 + 0xfe); // str len
        m_serializer->out_i64_at(m_encr_base + 1, m_secret_chat->key_fingerprint()); // fingerprint
        m_serializer->out_i32_at(m_encr_base + 1 + 2 + 4, length * 4); // len

        const int32_t* encr_ptr = m_serializer->i32_data() + m_encr_base + 1 + 2 + 4;
        const int32_t* encr_end = m_serializer->i32_data() + m_serializer->i32_size();

        unsigned char sha1_buffer[20];
        memset(sha1_buffer, 0, sizeof(sha1_buffer));
        TGLC_sha1(reinterpret_cast<const unsigned char*>(encr_ptr), (length + 1) * 4, sha1_buffer);
        m_serializer->out_i32s_at(m_encr_base + 1 + 2, reinterpret_cast<int32_t*>(sha1_buffer + 4), 4); // msg_key

        encrypt_decrypted_message(m_secret_chat, sha1_buffer, encr_ptr, encr_end, reinterpret_cast<char*>(const_cast<int32_t*>(encr_ptr)));
    }

private:
    std::shared_ptr<tgl_secret_chat> m_secret_chat;
    std::shared_ptr<mtprotocol_serializer> m_serializer;
    size_t m_encr_base;
};

void encrypt_decrypted_message(const std::shared_ptr<tgl_secret_chat>& secret_chat,
        const unsigned char msg_sha[20], const int32_t* encr_ptr, const int32_t* encr_end, char* encrypted_data) {
  unsigned char sha1a_buffer[20];
  unsigned char sha1b_buffer[20];
  unsigned char sha1c_buffer[20];
  unsigned char sha1d_buffer[20];
  memset(sha1a_buffer, 0, sizeof(sha1a_buffer));
  memset(sha1b_buffer, 0, sizeof(sha1b_buffer));
  memset(sha1c_buffer, 0, sizeof(sha1c_buffer));
  memset(sha1d_buffer, 0, sizeof(sha1d_buffer));

  const unsigned char* msg_key = msg_sha + 4;
 
  unsigned char buf[64];
  memset(buf, 0, sizeof(buf));
  const int* encryption_key = reinterpret_cast<const int*>(secret_chat->key());
  memcpy (buf, msg_key, 16);
  memcpy (buf + 16, encryption_key, 32);
  TGLC_sha1 (buf, 48, sha1a_buffer);
  
  memcpy (buf, encryption_key + 8, 16);
  memcpy (buf + 16, msg_key, 16);
  memcpy (buf + 32, encryption_key + 12, 16);
  TGLC_sha1 (buf, 48, sha1b_buffer);
  
  memcpy (buf, encryption_key + 16, 32);
  memcpy (buf + 32, msg_key, 16);
  TGLC_sha1 (buf, 48, sha1c_buffer);
  
  memcpy (buf, msg_key, 16);
  memcpy (buf + 16, encryption_key + 24, 32);
  TGLC_sha1 (buf, 48, sha1d_buffer);

  static unsigned char key[32];
  memcpy (key, sha1a_buffer + 0, 8);
  memcpy (key + 8, sha1b_buffer + 8, 12);
  memcpy (key + 20, sha1c_buffer + 4, 12);

  static unsigned char iv[32];
  memcpy (iv, sha1a_buffer + 8, 12);
  memcpy (iv + 12, sha1b_buffer + 0, 8);
  memcpy (iv + 20, sha1c_buffer + 16, 4);
  memcpy (iv + 24, sha1d_buffer + 0, 8);

  TGLC_aes_key aes_key;
  TGLC_aes_set_encrypt_key (key, 256, &aes_key);
  TGLC_aes_ige_encrypt (reinterpret_cast<const unsigned char*>(encr_ptr), reinterpret_cast<unsigned char*>(encrypted_data), 4 * (encr_end - encr_ptr), &aes_key, iv, 1);
  memset (&aes_key, 0, sizeof (aes_key));
}

static void do_set_dh_params(const std::shared_ptr<tgl_secret_chat>& secret_chat, int root, unsigned char prime[], int version)
{
    secret_chat->encr_root = root;
    secret_chat->set_encr_prime(prime, 256);
    secret_chat->encr_param_version = version;

    auto res = tglmp_check_DH_params(secret_chat->encr_prime_bn(), secret_chat->encr_root);
    TGL_ASSERT_UNUSED(res, res >= 0);
}

static void secret_chat_deleted(const std::shared_ptr<tgl_secret_chat>& secret_chat)
{
     tgl_secret_chat_state state = sc_deleted;
     tgl_update_secret_chat(secret_chat,
         NULL,
         NULL,
         NULL,
         NULL,
         NULL,
         NULL,
         &state,
         NULL,
         NULL,
         NULL,
         NULL,
         NULL,
         TGL_FLAGS_UNCHANGED);
}

void tgl_update_secret_chat(const std::shared_ptr<tgl_secret_chat>& secret_chat,
        const long long* access_hash,
        const int* date,
        const int* admin,
        const int* user_id,
        const unsigned char* key,
        const unsigned char* g_key,
        const tgl_secret_chat_state* state,
        const int* ttl,
        const int* layer,
        const int* in_seq_no,
        const int* last_in_seq_no,
        const int* out_seq_no,
        int flags)
{
    assert(secret_chat);

    if ((flags & TGLPF_CREATE) && (flags != TGL_FLAGS_UNCHANGED)) {
        assert(!(secret_chat->flags & TGLPF_CREATED));
    } else {
        assert(secret_chat->flags & TGLPF_CREATED);
    }

    if (flags == TGL_FLAGS_UNCHANGED) {
        flags = secret_chat->flags;
    }
    flags &= TGLECF_TYPE_MASK;

    secret_chat->flags = (secret_chat->flags & ~TGLECF_TYPE_MASK) | flags;

    if (access_hash && *access_hash != secret_chat->access_hash) {
        secret_chat->access_hash = *access_hash;
        secret_chat->id.access_hash = *access_hash;
    }

    if (date) {
        secret_chat->date = *date;
    }

    if (admin) {
        secret_chat->admin_id = *admin;
    }

    if (user_id) {
        secret_chat->user_id = *user_id;
    }

    if (in_seq_no) {
        secret_chat->in_seq_no = *in_seq_no;
    }

    if (out_seq_no) {
        secret_chat->out_seq_no = *out_seq_no;
    }

    if (last_in_seq_no) {
        secret_chat->last_in_seq_no = *last_in_seq_no;
    }

    if (g_key) {
        secret_chat->g_key.resize(256);
        std::copy(g_key, g_key + 256, secret_chat->g_key.begin());
    }

    if (key) {
        secret_chat->set_key(key);
    }

    auto old_state = secret_chat->state;
    if (state) {
        if (secret_chat->state == sc_waiting && *state == sc_ok) {
            tgl_do_create_keys_end(secret_chat);
        }
        secret_chat->state = *state;
    }

    tgl_state::instance()->callback()->secret_chat_update(secret_chat, old_state);
}

/* }}} */

static void tgl_do_send_encr_action(const std::shared_ptr<tgl_secret_chat>& secret_chat, const tl_ds_decrypted_message_action& action) {
  long long t;
  tglt_secure_random ((unsigned char*)&t, 8);
  int date = time (0);

  struct tgl_message_id msg_id = tgl_peer_id_to_random_msg_id(secret_chat->id);
  
  tgl_peer_id_t from_id = tgl_state::instance()->our_id();
  std::shared_ptr<tgl_message> M = tglm_create_encr_message(&msg_id,
      &from_id,
      &secret_chat->id,
      &date,
      NULL,
      0,
      NULL,
      &action,
      NULL,
      TGLMF_PENDING | TGLMF_OUT | TGLMF_UNREAD | TGLMF_CREATE | TGLMF_CREATED | TGLMF_ENCRYPTED);

  assert (M);
  tgl_do_send_msg (M, 0);
}

void tgl_do_send_encr_chat_layer(const std::shared_ptr<tgl_secret_chat>& secret_chat) {
    static struct tl_ds_decrypted_message_action action;
    action.magic = CODE_decrypted_message_action_notify_layer;
    int layer = TGL_ENCRYPTED_LAYER;
    action.layer = &layer;

    tgl_do_send_encr_action(secret_chat, action);
}

void tgl_do_send_encr_chat_request_resend(const std::shared_ptr<tgl_secret_chat>& secret_chat, int start_seq_no, int end_seq_no)
{
    static struct tl_ds_decrypted_message_action action;
    action.magic = CODE_decrypted_message_action_resend;
    action.start_seq_no = &start_seq_no;
    action.end_seq_no = &end_seq_no;

    tgl_do_send_encr_action(secret_chat, action);
}

void tgl_do_set_encr_chat_ttl(const std::shared_ptr<tgl_secret_chat>& secret_chat, int ttl) {
    static struct tl_ds_decrypted_message_action action;
    action.magic = CODE_decrypted_message_action_set_message_t_t_l;
    action.ttl_seconds = &ttl;

    tgl_do_send_encr_action(secret_chat, action);
}

class query_msg_send_encr: public query {
public:
    query_msg_send_encr(
            const std::shared_ptr<tgl_secret_chat>& secret_chat,
            const std::shared_ptr<tgl_message>& message,
            const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback)
        : query("send encrypted (message)", TYPE_TO_PARAM(messages_sent_encrypted_message))
        , m_secret_chat(secret_chat)
        , m_message(message)
        , m_callback(callback)
    {
    }

    virtual void on_answer(void*) override
    {
        tgl_state::instance()->callback()->message_sent(m_message, m_message->permanent_id.id, m_secret_chat->out_seq_no);
        if (m_callback) {
            m_callback(true, m_message);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        if (m_secret_chat && m_secret_chat->state != sc_deleted && error_code == 400 && error_string == "ENCRYPTION_DECLINED") {
            secret_chat_deleted(m_secret_chat);
        }

        if (m_callback) {
            m_callback(false, m_message);
        }

        if (m_message) {
            //bl_do_message_delete (&M->permanent_id);
            // FIXME: is this correct?
            tgl_state::instance()->callback()->message_deleted(m_message->permanent_id.id);
        }
        return 0;
    }

private:
    std::shared_ptr<tgl_secret_chat> m_secret_chat;
    std::shared_ptr<tgl_message> m_message;
    std::function<void(bool, const std::shared_ptr<tgl_message>&)> m_callback;
};

void tgl_do_send_encr_msg_action (const std::shared_ptr<tgl_message>& M, std::function<void(bool, const std::shared_ptr<tgl_message>& M)> callback)
{
  std::shared_ptr<tgl_secret_chat> secret_chat = tgl_state::instance()->secret_chat_for_id(TGL_MK_ENCR_CHAT(M->permanent_id.peer_id));
  if (!secret_chat || secret_chat->state != sc_ok) { 
    TGL_WARNING("Unknown encrypted chat");
    if (callback) {
      callback(0, 0);
    }
    return;
  }
 
  assert (M->flags & TGLMF_ENCRYPTED);
  assert(M->action);

  auto q = std::make_shared<query_msg_send_encr>(secret_chat, M, callback);
  secret_chat_encryptor encryptor(secret_chat, q->serializer());
  q->out_i32 (CODE_messages_send_encrypted_service);
  q->out_i32 (CODE_input_encrypted_chat);
  q->out_i32 (M->permanent_id.peer_id);
  q->out_i64 (M->permanent_id.access_hash);
  q->out_i64 (M->permanent_id.id);
  encryptor.start();
  q->out_i32 (CODE_decrypted_message_layer);
  q->out_random (15 + 4 * (rand () % 3));
  q->out_i32 (TGL_ENCRYPTED_LAYER);
  q->out_i32 (2 * secret_chat->in_seq_no + (secret_chat->admin_id != tgl_get_peer_id (tgl_state::instance()->our_id())));
  q->out_i32 (2 * secret_chat->out_seq_no + (secret_chat->admin_id == tgl_get_peer_id (tgl_state::instance()->our_id())) - 2);
  q->out_i32 (CODE_decrypted_message_service);
  q->out_i64 (M->permanent_id.id);

  switch (M->action->type()) {
  case tgl_message_action_type_notify_layer:
    q->out_i32 (CODE_decrypted_message_action_notify_layer);
    q->out_i32 (std::static_pointer_cast<tgl_message_action_notify_layer>(M->action)->layer);
    break;
  case tgl_message_action_type_set_message_ttl:
    q->out_i32 (CODE_decrypted_message_action_set_message_t_t_l);
    q->out_i32 (std::static_pointer_cast<tgl_message_action_set_message_ttl>(M->action)->ttl);
    break;
  case tgl_message_action_type_request_key:
  {
    auto action = std::static_pointer_cast<tgl_message_action_request_key>(M->action);
    q->out_i32 (CODE_decrypted_message_action_request_key);
    q->out_i64 (action->exchange_id);
    q->out_string (reinterpret_cast<char*>(action->g_a.data()), 256);
    break;
  }
  case tgl_message_action_type_accept_key:
  {
    auto action = std::static_pointer_cast<tgl_message_action_accept_key>(M->action);
    q->out_i32 (CODE_decrypted_message_action_accept_key);
    q->out_i64 (action->exchange_id);
    q->out_string (reinterpret_cast<char*>(action->g_a.data()), 256);
    q->out_i64 (action->key_fingerprint);
    break;
  }
  case tgl_message_action_type_commit_key:
  {
    auto action = std::static_pointer_cast<tgl_message_action_commit_key>(M->action);
    q->out_i32 (CODE_decrypted_message_action_commit_key);
    q->out_i64 (action->exchange_id);
    q->out_i64 (action->key_fingerprint);
    break;
  }
  case tgl_message_action_type_abort_key:
  {
    auto action = std::static_pointer_cast<tgl_message_action_abort_key>(M->action);
    q->out_i32 (CODE_decrypted_message_action_abort_key);
    q->out_i64 (action->exchange_id);
    break;
  }
  case tgl_message_action_type_noop:
    q->out_i32 (CODE_decrypted_message_action_noop);
    break;
  case tgl_message_action_type_resend:
  {
    auto action = std::static_pointer_cast<tgl_message_action_resend>(M->action);
    q->out_i32 (CODE_decrypted_message_action_resend);
    q->out_i32 (action->start_seq_no);
    q->out_i32 (action->end_seq_no);
    break;
  }
  default:
    assert (0);
  }
  encryptor.end();
  q->execute(tgl_state::instance()->DC_working);
}

void tgl_do_send_encr_msg (const std::shared_ptr<tgl_message>& M, std::function<void(bool, const std::shared_ptr<tgl_message>& M)> callback)
{
  if (M->flags & TGLMF_SERVICE) {
    if (!M->action) {
      return;
    }
    tgl_do_send_encr_msg_action(M, callback);
    return;
  }
  std::shared_ptr<tgl_secret_chat> secret_chat = tgl_state::instance()->secret_chat_for_id(TGL_MK_ENCR_CHAT(M->permanent_id.peer_id));
  if (!secret_chat || secret_chat->state != sc_ok) { 
    TGL_WARNING("Unknown encrypted chat");
    if (callback) {
      callback(0, M);
    }
    return;
  }
  
  assert (M->flags & TGLMF_ENCRYPTED);

  auto q = std::make_shared<query_msg_send_encr>(secret_chat, M, callback);
  secret_chat_encryptor encryptor(secret_chat, q->serializer());
  q->out_i32 (CODE_messages_send_encrypted);
  q->out_i32 (CODE_input_encrypted_chat);
  q->out_i32 (tgl_get_peer_id (M->to_id));
  q->out_i64 (secret_chat->access_hash);
  q->out_i64 (M->permanent_id.id);
  encryptor.start();
  q->out_i32 (CODE_decrypted_message_layer);
  q->out_random (15 + 4 * (rand () % 3));
  q->out_i32 (TGL_ENCRYPTED_LAYER);
  q->out_i32 (2 * secret_chat->in_seq_no + (secret_chat->admin_id != tgl_get_peer_id (tgl_state::instance()->our_id())));
  q->out_i32 (2 * secret_chat->out_seq_no + (secret_chat->admin_id == tgl_get_peer_id (tgl_state::instance()->our_id())) - 2);
  q->out_i32 (CODE_decrypted_message);
  q->out_i64 (M->permanent_id.id);
  q->out_i32 (secret_chat->ttl);
  q->out_string (M->message.c_str(), M->message.size());

  assert(M->media);

  switch (M->media->type()) {
  case tgl_message_media_type_none:
    q->out_i32 (CODE_decrypted_message_media_empty);
    break;
  case tgl_message_media_type_geo:
  {
    auto media = std::static_pointer_cast<tgl_message_media_geo>(M->media);
    q->out_i32 (CODE_decrypted_message_media_geo_point);
    q->out_double (media->geo.latitude);
    q->out_double (media->geo.longitude);
    break;
  }
  default:
    assert (0);
  }
  encryptor.end();
  
  q->execute(tgl_state::instance()->DC_working);
}

class query_mark_read_encr: public query
{
public:
    query_mark_read_encr(
            const std::shared_ptr<tgl_secret_chat>& secret_chat,
            const std::function<void(bool)>& callback)
        : query("read encrypted", TYPE_TO_PARAM(bool))
        , m_secret_chat(secret_chat)
        , m_callback(callback)
    { }

    virtual void on_answer(void*) override
    {
        if (m_callback) {
            m_callback(true);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        if (m_secret_chat->state != sc_deleted && error_code == 400 && error_string == "ENCRYPTION_DECLINED") {
            secret_chat_deleted(m_secret_chat);
        }

        if (m_callback) {
            m_callback(false);
        }

        return 0;
    }

private:
    std::shared_ptr<tgl_secret_chat> m_secret_chat;
    std::function<void(bool)> m_callback;
};

void tgl_do_messages_mark_read_encr(const std::shared_ptr<tgl_secret_chat>& secret_chat, std::function<void(bool)> callback) {
    auto q = std::make_shared<query_mark_read_encr>(secret_chat, callback);
    q->out_i32(CODE_messages_read_encrypted_history);
    q->out_i32(CODE_input_encrypted_chat);
    q->out_i32(tgl_get_peer_id (secret_chat->id));
    q->out_i64(secret_chat->access_hash);
    q->out_i32(secret_chat->last ? secret_chat->last->date : time (0) - 10);
    q->execute(tgl_state::instance()->DC_working);
}

class query_send_encr_file: public query
{
public:
    query_send_encr_file(
            const std::shared_ptr<tgl_secret_chat>& secret_chat,
            const std::shared_ptr<tgl_message>& message,
            const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback)
        : query("send encrypted (file)", TYPE_TO_PARAM(messages_sent_encrypted_message))
        , m_secret_chat(secret_chat)
        , m_message(message)
        , m_callback(callback)
    { }

    void set_message(const std::shared_ptr<tgl_message>& message)
    {
        m_message = message;
    }

    virtual void on_answer(void*) override
    {
#if 0 // FIXME
        struct tl_ds_messages_sent_encrypted_message *DS_MSEM = (struct tl_ds_messages_sent_encrypted_message*)D;
        struct tgl_message *M = q->extra;

        if (M->flags & TGLMF_PENDING) {
          //bl_do_edit_message_encr (&M->permanent_id, NULL, NULL, DS_MSEM->date,
          //NULL, 0, NULL, NULL, DS_MSEM->file, M->flags ^ TGLMF_PENDING);
          //bl_do_msg_update (&M->permanent_id);
          tgl_state::instance()->callback.new_msg(M);
        }
#endif
        if (m_callback) {
            m_callback(true, m_message);
        }
        tgl_state::instance()->callback()->message_sent(m_message, m_message->permanent_id.id, m_secret_chat->out_seq_no);
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        if (m_secret_chat && m_secret_chat->state != sc_deleted && error_code == 400 && error_string == "ENCRYPTION_DECLINED") {
            secret_chat_deleted(m_secret_chat);
        }

        if (m_callback) {
            m_callback(false, m_message);
        }

        if (m_message) {
            //bl_do_message_delete (&M->permanent_id);
            // FIXME: is this correct?
            tgl_state::instance()->callback()->message_deleted(m_message->permanent_id.id);
        }
        return 0;
    }

private:
    std::shared_ptr<tgl_secret_chat> m_secret_chat;
    std::shared_ptr<tgl_message> m_message;
    std::function<void(bool, const std::shared_ptr<tgl_message>&)> m_callback;
};

void send_file_encrypted_end (std::shared_ptr<send_file> f, const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback) {
  std::shared_ptr<tgl_secret_chat> secret_chat = tgl_state::instance()->secret_chat_for_id(f->to_id);
  assert(secret_chat);
  auto q = std::make_shared<query_send_encr_file>(secret_chat, nullptr, callback);
  secret_chat_encryptor encryptor(secret_chat, q->serializer());
  q->out_i32 (CODE_messages_send_encrypted_file);
  q->out_i32 (CODE_input_encrypted_chat);
  q->out_i32 (tgl_get_peer_id (f->to_id));
  q->out_i64 (secret_chat->access_hash);
  long long r;
  tglt_secure_random (reinterpret_cast<unsigned char*>(&r), 8);
  q->out_i64 (r);
  encryptor.start();
  q->out_i32 (CODE_decrypted_message_layer);
  q->out_random (15 + 4 * (rand () % 3));
  q->out_i32 (TGL_ENCRYPTED_LAYER);
  q->out_i32 (2 * secret_chat->in_seq_no + (secret_chat->admin_id != tgl_get_peer_id (tgl_state::instance()->our_id())));
  q->out_i32 (2 * secret_chat->out_seq_no + (secret_chat->admin_id == tgl_get_peer_id (tgl_state::instance()->our_id())));
  q->out_i32 (CODE_decrypted_message);
  q->out_i64 (r);
  q->out_i32 (secret_chat->ttl);
  q->out_string ("");

  // FIXME: We don't have to use mutable one but the C code of in_ptr doesn't use const.
  int32_t *save_ptr = q->serializer()->mutable_i32_data() + q->serializer()->i32_size();

  if (f->flags == -1) {
    q->out_i32 (CODE_decrypted_message_media_photo);
  } else if ((f->flags & TGLDF_VIDEO)) {
    q->out_i32 (CODE_decrypted_message_media_video);
  } else if ((f->flags & TGLDF_AUDIO)) {
    q->out_i32 (CODE_decrypted_message_media_audio);
  } else {
    q->out_i32 (CODE_decrypted_message_media_document);
  }
  if (f->flags == -1 || !(f->flags & TGLDF_AUDIO)) {
    q->out_string ("", 0);
    q->out_i32 (90);
    q->out_i32 (90);
  }
  
  if (f->flags == -1) {
    q->out_i32 (f->w);
    q->out_i32 (f->h);
  } else if (f->flags & TGLDF_VIDEO) {
    q->out_i32 (f->duration);
    q->out_string (tg_mime_by_filename (f->file_name.c_str()));
    q->out_i32 (f->w);
    q->out_i32 (f->h);
  } else if (f->flags & TGLDF_AUDIO) {
    q->out_i32 (f->duration);
    q->out_string (tg_mime_by_filename (f->file_name.c_str()));
  } else {
    // FIXME: for no '/' sepearator filesystems.
    auto filename = f->file_name;
    auto pos = filename.rfind('/');
    if (pos != std::string::npos) {
        filename = filename.substr(pos + 1);
    }
    q->out_string (filename.c_str());
    q->out_string (tg_mime_by_filename (f->file_name.c_str()));
    // document
  }
  
  q->out_i32 (f->size);
  q->out_string (reinterpret_cast<const char*>(f->key), 32);
  q->out_string (reinterpret_cast<const char*>(f->init_iv), 32);
 
  int *save_in_ptr = in_ptr;
  int *save_in_end = in_end;

  in_ptr = save_ptr;
  in_end = q->serializer()->mutable_i32_data() + q->serializer()->i32_size();

  struct paramed_type decrypted_message_media = TYPE_TO_PARAM(decrypted_message_media);
  auto result = skip_type_any (&decrypted_message_media);
  TGL_ASSERT_UNUSED(result, result >= 0);
  assert (in_ptr == in_end);
  
  in_ptr = save_ptr;
  in_end = q->serializer()->mutable_i32_data() + q->serializer()->i32_size();
  
  struct tl_ds_decrypted_message_media *DS_DMM = fetch_ds_type_decrypted_message_media (&decrypted_message_media);
  in_end = save_in_ptr;
  in_ptr = save_in_end;

  encryptor.end();

  if (f->size < (16 << 20)) {
    q->out_i32 (CODE_input_encrypted_file_uploaded);
  } else {
    q->out_i32 (CODE_input_encrypted_file_big_uploaded);
  }
  q->out_i64 (f->id);
  q->out_i32 (f->part_num);
  if (f->size < (16 << 20)) {
    q->out_string ("");
  }

  unsigned char md5[16];
  unsigned char str[64];
  memcpy (str, f->key, 32);
  memcpy (str + 32, f->init_iv, 32);
  TGLC_md5 (str, 64, md5);
  q->out_i32 ((*(int *)md5) ^ (*(int *)(md5 + 4)));

  tfree_secure (f->iv, 32);
 
  tgl_peer_id_t from_id = tgl_state::instance()->our_id();
  
  int date = time (NULL);
  struct tgl_message_id msg_id = tgl_peer_id_to_msg_id(secret_chat->id, r);
  std::shared_ptr<tgl_message> M = tglm_create_encr_message(&msg_id,
      &from_id,
      &f->to_id,
      &date,
      NULL,
      0,
      DS_DMM,
      NULL,
      NULL,
      TGLMF_OUT | TGLMF_UNREAD | TGLMF_ENCRYPTED | TGLMF_CREATE | TGLMF_CREATED);

  free_ds_type_decrypted_message_media (DS_DMM, &decrypted_message_media);
  assert (M);
  q->set_message(M);

  q->execute(tgl_state::instance()->DC_working);
}

void tgl_do_send_location_encr(const tgl_peer_id_t& id, double latitude, double longitude, unsigned long long flags, std::function<void(bool success, const std::shared_ptr<tgl_message>& M)> callback)
{
  struct tl_ds_decrypted_message_media TDSM;
  TDSM.magic = CODE_decrypted_message_media_geo_point;
  TDSM.latitude = (double*)talloc (sizeof (double));
  *TDSM.latitude = latitude;
  TDSM.longitude = (double*)talloc (sizeof (double));
  *TDSM.longitude = longitude;
  
  int date = time (0);

  tgl_peer_id_t from_id = tgl_state::instance()->our_id();

  //tgl_peer_t *P = tgl_peer_get (id);
  std::shared_ptr<tgl_secret_chat> secret_chat = tgl_state::instance()->secret_chat_for_id(id);
  assert(secret_chat);
  
  struct tgl_message_id msg_id = tgl_peer_id_to_random_msg_id (id);;
  std::shared_ptr<tgl_message> M = tglm_create_encr_message(&msg_id,
      &from_id,
      &id,
      &date,
      NULL,
      0,
      &TDSM,
      NULL,
      NULL,
      TGLMF_UNREAD | TGLMF_OUT | TGLMF_PENDING | TGLMF_CREATE | TGLMF_CREATED | TGLMF_ENCRYPTED);

  free(TDSM.latitude);
  free(TDSM.longitude);

  tgl_do_send_encr_msg(M, callback);
}

class query_send_encr_accept: public query
{
public:
    query_send_encr_accept(const std::shared_ptr<tgl_secret_chat>& secret_chat,
            const std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)>& callback)
        : query("send encrypted (chat accept)", TYPE_TO_PARAM(encrypted_chat))
        , m_secret_chat(secret_chat)
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        std::shared_ptr<tgl_secret_chat> secret_chat = tglf_fetch_alloc_encrypted_chat(
                static_cast<tl_ds_encrypted_chat*>(D));

        if (secret_chat && secret_chat->state == sc_ok) {
            tgl_do_send_encr_chat_layer(secret_chat);
        }

        if (secret_chat) {
            assert(m_secret_chat == secret_chat);
        }

        if (m_callback) {
            m_callback(secret_chat && secret_chat->state == sc_ok, secret_chat);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        if (m_secret_chat && m_secret_chat->state != sc_deleted && error_code == 400 && error_string == "ENCRYPTION_DECLINED") {
            secret_chat_deleted(m_secret_chat);
        }

        if (m_callback) {
            m_callback(false, nullptr);
        }
        return 0;
    }

private:
    std::shared_ptr<tgl_secret_chat> m_secret_chat;
    std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)> m_callback;
};

class query_send_encr_request: public query
{
public:
    explicit query_send_encr_request(
            const std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)>& callback)
        : query("send encrypted (chat request)", TYPE_TO_PARAM(encrypted_chat))
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        std::shared_ptr<tgl_secret_chat> secret_chat = tglf_fetch_alloc_encrypted_chat(
                static_cast<tl_ds_encrypted_chat*>(D));

        if (m_callback) {
            m_callback(secret_chat && secret_chat->state != sc_deleted, secret_chat);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false, nullptr);
        }

        return 0;
    }

private:
    std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)> m_callback;
};

static void tgl_do_send_accept_encr_chat(const std::shared_ptr<tgl_secret_chat>& secret_chat,
        std::array<unsigned char, 256>& random,
        std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)> callback)
{
  int i;
  int ok = 0;
  const int* key = reinterpret_cast<const int*>(secret_chat->key());
  for (i = 0; i < 64; i++) {
    if (key[i]) {
      ok = 1;
      break;
    }
  }
  if (ok) { 
    if (callback) {
      callback (1, secret_chat);
    }
    return; 
  } // Already generated key for this chat
  assert (!secret_chat->g_key.empty());
  assert (tgl_state::instance()->bn_ctx);
  unsigned char random_here[256];
  tglt_secure_random (random_here, 256);
  for (i = 0; i < 256; i++) {
    random[i] ^= random_here[i];
  }
  TGLC_bn *b = TGLC_bn_bin2bn (random.data(), 256, 0);
  ensure_ptr (b);
  TGLC_bn *g_a = TGLC_bn_bin2bn (secret_chat->g_key.data(), 256, 0);
  ensure_ptr (g_a);
  auto res = tglmp_check_g_a(secret_chat->encr_prime_bn(), g_a);
  TGL_ASSERT_UNUSED(res, res >= 0);
  //if (!ctx) {
  //  ctx = TGLC_bn_ctx_new ();
  //  ensure_ptr (ctx);
  //}
  TGLC_bn *p = secret_chat->encr_prime_bn();
  TGLC_bn *r = TGLC_bn_new ();
  ensure_ptr (r);
  ensure (TGLC_bn_mod_exp (r, g_a, b, p, tgl_state::instance()->bn_ctx));
  static unsigned char kk[256];
  memset (kk, 0, sizeof (kk));
  TGLC_bn_bn2bin (r, kk + (256 - TGLC_bn_num_bytes (r)));

  tgl_secret_chat_state state = sc_ok;

  tgl_update_secret_chat(secret_chat,
          NULL,
          NULL,
          NULL,
          NULL,
          kk,
          NULL,
          &state,
          NULL,
          NULL,
          NULL,
          NULL,
          NULL,
          TGL_FLAGS_UNCHANGED);

  auto q = std::make_shared<query_send_encr_accept>(secret_chat, callback);
  q->out_i32 (CODE_messages_accept_encryption);
  q->out_i32 (CODE_input_encrypted_chat);
  q->out_i32 (tgl_get_peer_id (secret_chat->id));
  q->out_i64 (secret_chat->access_hash);
  
  ensure (TGLC_bn_set_word (g_a, secret_chat->encr_root));
  ensure (TGLC_bn_mod_exp (r, g_a, b, p, tgl_state::instance()->bn_ctx));
  static unsigned char buf[256];
  memset (buf, 0, sizeof (buf));
  TGLC_bn_bn2bin (r, buf + (256 - TGLC_bn_num_bytes (r)));
  q->out_string (reinterpret_cast<const char*>(buf), 256);

  q->out_i64 (secret_chat->key_fingerprint());
  TGLC_bn_clear_free (b);
  TGLC_bn_clear_free (g_a);
  TGLC_bn_clear_free (r);

  q->execute(tgl_state::instance()->DC_working);
}

void tgl_do_create_keys_end(const std::shared_ptr<tgl_secret_chat>& secret_chat) {
  assert (!secret_chat->encr_prime().empty());
  TGLC_bn *g_b = TGLC_bn_bin2bn (secret_chat->g_key.data(), 256, 0);
  ensure_ptr (g_b);
  auto res = tglmp_check_g_a (secret_chat->encr_prime_bn(), g_b);
  TGL_ASSERT_UNUSED(res, res >= 0);
  
  TGLC_bn *p = secret_chat->encr_prime_bn();
  ensure_ptr (p);
  TGLC_bn *r = TGLC_bn_new ();
  ensure_ptr (r);
  TGLC_bn *a = TGLC_bn_bin2bn (secret_chat->key(), tgl_secret_chat::key_size(), 0);
  ensure_ptr (a);
  ensure (TGLC_bn_mod_exp (r, g_b, a, p, tgl_state::instance()->bn_ctx));

  std::vector<unsigned char> key(tgl_secret_chat::key_size(), 0);

  TGLC_bn_bn2bin(r, (key.data() + (tgl_secret_chat::key_size() - TGLC_bn_num_bytes (r))));
  secret_chat->set_key(key.data());
  
  if (secret_chat->key_fingerprint() != secret_chat->temp_key_fingerprint) {
    TGL_WARNING("Key fingerprint mismatch (my 0x" << std::hex
        << (unsigned long long)secret_chat->key_fingerprint()
        << "x 0x" << (unsigned long long)secret_chat->temp_key_fingerprint << "x)");
    secret_chat->state = sc_deleted;
  }
  secret_chat->temp_key_fingerprint = 0;
  
  TGLC_bn_clear_free (g_b);
  TGLC_bn_clear_free (a);
}

static void tgl_do_send_create_encr_chat(const std::shared_ptr<tgl_secret_chat>& secret_chat,
        std::array<unsigned char, 256>& random,
        std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)> callback)
{
  int i;
  unsigned char random_here[256];
  tglt_secure_random (random_here, 256);
  for (i = 0; i < 256; i++) {
    random[i] ^= random_here[i];
  }
  TGLC_bn *a = TGLC_bn_bin2bn (random.data(), 256, 0);
  ensure_ptr (a);
  TGLC_bn *p = TGLC_bn_bin2bn (secret_chat->encr_prime().data(), 256, 0);
  ensure_ptr (p);
 
  TGLC_bn *g = TGLC_bn_new ();
  ensure_ptr (g);

  ensure (TGLC_bn_set_word (g, secret_chat->encr_root));

  TGLC_bn *r = TGLC_bn_new ();
  ensure_ptr (r);

  ensure (TGLC_bn_mod_exp (r, g, a, p, tgl_state::instance()->bn_ctx));

  TGLC_bn_clear_free (a);

  static char g_a[256];
  memset (g_a, 0, 256);

  TGLC_bn_bn2bin (r, reinterpret_cast<unsigned char*>(g_a + (256 - TGLC_bn_num_bytes (r))));
  
  //bl_do_encr_chat_init (t, &secret_chat->user_id, (void *)random, (void *)g_a);
  
  tgl_secret_chat_state state = sc_waiting;
  int our_id = tgl_get_peer_id (tgl_state::instance()->our_id());
  tgl_update_secret_chat(secret_chat,
        NULL,
        NULL,
        &our_id,
        NULL,
        random.data(),
        NULL,
        &state,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        TGLPF_CREATE | TGLPF_CREATED);

  auto q = std::make_shared<query_send_encr_request>(callback);
  q->out_i32 (CODE_messages_request_encryption);
  
  q->out_i32 (CODE_input_user);
  q->out_i32 (secret_chat->user_id);
  q->out_i64(secret_chat->access_hash);

  q->out_i32 (tgl_get_peer_id (secret_chat->id));
  q->out_string (g_a, 256);
  //write_secret_chat_file ();
  
  TGLC_bn_clear_free (g);
  TGLC_bn_clear_free (p);
  TGLC_bn_clear_free (r);

  q->execute(tgl_state::instance()->DC_working);
}

class query_send_encr_discard: public query
{
public:
    query_send_encr_discard(
            const std::shared_ptr<tgl_secret_chat>& secret_chat,
            const std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)>& callback)
        : query("send encrypted (chat discard)", TYPE_TO_PARAM(bool))
        , m_secret_chat(secret_chat)
        , m_callback(callback)
    { }

    virtual void on_answer(void*) override
    {
        if (m_callback) {
            m_callback(true, m_secret_chat);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false, m_secret_chat);
        }
        return 0;
    }

private:
    std::shared_ptr<tgl_secret_chat> m_secret_chat;
    std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)> m_callback;
};

void tgl_do_discard_secret_chat(const std::shared_ptr<tgl_secret_chat>& secret_chat, std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)> callback) {
  assert (secret_chat);
  assert (tgl_get_peer_id (secret_chat->id) > 0);

  if (secret_chat->state == sc_deleted || secret_chat->state == sc_none) {
    if (callback) {
      callback (false, secret_chat);
    }
    return;
  }

  auto q = std::make_shared<query_send_encr_discard>(secret_chat, callback);
  q->out_i32 (CODE_messages_discard_encryption);
  q->out_i32 (tgl_get_peer_id (secret_chat->id));

  q->execute(tgl_state::instance()->DC_working);
}

class query_get_dh_config: public query
{
public:
    query_get_dh_config(const std::shared_ptr<tgl_secret_chat>& secret_chat,
            const std::function<void(const std::shared_ptr<tgl_secret_chat>&,
                    std::array<unsigned char, 256>& random,
                    const std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)>&)>& callback,
            const std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)>& final_callback)
        : query("get dh config", TYPE_TO_PARAM(messages_dh_config))
        , m_secret_chat(secret_chat)
        , m_callback(callback)
        , m_final_callback(final_callback)
    { }

    virtual void on_answer(void* D) override
    {
        tl_ds_messages_dh_config* DS_MDC = static_cast<tl_ds_messages_dh_config*>(D);

        if (DS_MDC->magic == CODE_messages_dh_config) {
            assert(DS_MDC->p->len == 256);
            do_set_dh_params(m_secret_chat, DS_LVAL(DS_MDC->g),
                    reinterpret_cast<unsigned char*>(DS_MDC->p->data), DS_LVAL(DS_MDC->version));
        } else {
            assert(m_secret_chat->encr_param_version);
        }

        if (m_callback) {
            std::array<unsigned char, 256> random;
            assert(DS_MDC->random->len == 256);
            memcpy(random.data(), DS_MDC->random->data, 256);
            m_callback(m_secret_chat, random, m_final_callback);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_final_callback) {
            m_final_callback(false, m_secret_chat);
        }
        return 0;
    }

private:
    std::shared_ptr<tgl_secret_chat> m_secret_chat;
    std::function<void(const std::shared_ptr<tgl_secret_chat>&,
             std::array<unsigned char, 256>& random,
             const std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)>&)> m_callback;
    std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)> m_final_callback;
};

void tgl_do_accept_encr_chat_request(const std::shared_ptr<tgl_secret_chat>& secret_chat, std::function<void(bool, const std::shared_ptr<tgl_secret_chat>& E)> callback) {
    if (secret_chat->state != sc_request) {
        if (callback) {
            callback (0, secret_chat);
        }
        return;
    }
    assert (secret_chat->state == sc_request);

    auto q = std::make_shared<query_get_dh_config>(secret_chat, tgl_do_send_accept_encr_chat, callback);
    q->out_i32 (CODE_messages_get_dh_config);
    q->out_i32 (secret_chat->encr_param_version);
    q->out_i32 (256);
    q->execute(tgl_state::instance()->DC_working);
}

void tgl_do_create_encr_chat_request(const tgl_peer_id_t& user_id,
        const std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)>& callback) {
    std::shared_ptr<tgl_secret_chat> secret_chat = tgl_state::instance()->create_secret_chat();
    secret_chat->user_id = user_id.peer_id;
    secret_chat->access_hash = user_id.access_hash;
    secret_chat->id.access_hash = user_id.access_hash;

    auto q = std::make_shared<query_get_dh_config>(secret_chat, tgl_do_send_create_encr_chat, callback);
    q->out_i32 (CODE_messages_get_dh_config);
    q->out_i32 (0);
    q->out_i32 (256);
    q->execute(tgl_state::instance()->DC_working);
}

void tgl_do_request_exchange(const std::shared_ptr<tgl_secret_chat>&) {
    assert(0);
    exit(2);
}

void tgl_do_accept_exchange(const std::shared_ptr<tgl_secret_chat>&, long long exchange_id, const std::vector<unsigned char>& ga) {
    assert(0);
    exit(2);
}

void tgl_do_confirm_exchange(const std::shared_ptr<tgl_secret_chat>&, int sen_nop) {
    assert(0);
    exit(2);
}

void tgl_do_commit_exchange(const std::shared_ptr<tgl_secret_chat>&, const std::vector<unsigned char>& gb) {
    assert(0);
    exit(2);
}

void tgl_do_abort_exchange(const std::shared_ptr<tgl_secret_chat>&) {
    assert(0);
    exit(2);
}

/* }}} */
#endif
