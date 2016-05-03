
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

/* {{{ Encrypt decrypted */
static int *encr_extra;
static int *encr_ptr;
static int *encr_end;

static void out_random (int n) {
    assert (n <= 32);
    static unsigned char buf[32];
    tglt_secure_random (buf, n);
    out_cstring ((char*)buf, n);
}

static char *encrypt_decrypted_message (struct tgl_secret_chat* secret_chat) {
  static int msg_key[4];
  static unsigned char sha1a_buffer[20];
  static unsigned char sha1b_buffer[20];
  static unsigned char sha1c_buffer[20];
  static unsigned char sha1d_buffer[20];
  int x = *(encr_ptr);  
  assert (x >= 0 && !(x & 3));
  TGLC_sha1(reinterpret_cast<const unsigned char*>(encr_ptr), 4 + x, sha1a_buffer);
  memcpy (msg_key, sha1a_buffer + 4, 16);
 
  static unsigned char buf[64];
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
  TGLC_aes_ige_encrypt (reinterpret_cast<const unsigned char*>(encr_ptr), reinterpret_cast<unsigned char*>(encr_ptr), 4 * (encr_end - encr_ptr), &aes_key, iv, 1);
  memset (&aes_key, 0, sizeof (aes_key));

  return reinterpret_cast<char*>(msg_key);
}

static void encr_start (void) {
    encr_extra = packet_ptr;
    packet_ptr += 1; // str len
    packet_ptr += 2; // fingerprint
    packet_ptr += 4; // msg_key
    packet_ptr += 1; // len
}


static void encr_finish (struct tgl_secret_chat* secret_chat) {
    int l = packet_ptr - (encr_extra +  8);
    while (((packet_ptr - encr_extra) - 3) & 3) {
        int t;
        tglt_secure_random ((unsigned char*)&t, 4);
        out_int (t);
    }

    *encr_extra = ((packet_ptr - encr_extra) - 1) * 4 * 256 + 0xfe;
    encr_extra ++;
    *(long long *)encr_extra = secret_chat->key_fingerprint();
    encr_extra += 2;
    encr_extra[4] = l * 4;
    encr_ptr = encr_extra + 4;
    encr_end = packet_ptr;
    memcpy(encr_extra, encrypt_decrypted_message(secret_chat), 16);
}

static void do_set_dh_params(const std::shared_ptr<tgl_secret_chat>& secret_chat, int root, unsigned char prime[], int version)
{
    secret_chat->encr_root = root;
    secret_chat->set_encr_prime(prime, 256);
    secret_chat->encr_param_version = version;

    auto res = tglmp_check_DH_params(secret_chat->encr_prime_bn(), secret_chat->encr_root);
    TGL_ASSERT_UNUSED(res, res >= 0);
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

class query_msg_send_encr: public query_v2 {
public:
    query_msg_send_encr(
            const std::shared_ptr<tgl_secret_chat>& secret_chat,
            const std::shared_ptr<tgl_message>& message,
            const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback)
        : query_v2("send encrypted (message)", TYPE_TO_PARAM(messages_sent_encrypted_message))
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
        if (m_secret_chat && m_secret_chat->state != sc_deleted && error_code == 400) {
            if (error_string == "ENCRYPTION_DECLINED") {
                // FIXME: delete the secret chat?
                //bl_do_peer_delete (tgl_state::instance(), secret_chat->id);
            }
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

  clear_packet ();
  out_int (CODE_messages_send_encrypted_service);
  out_int (CODE_input_encrypted_chat);
  out_int (M->permanent_id.peer_id);
  out_long (M->permanent_id.access_hash);
  out_long (M->permanent_id.id);
  encr_start ();
  out_int (CODE_decrypted_message_layer);
  out_random (15 + 4 * (rand () % 3));
  out_int (TGL_ENCRYPTED_LAYER);
  out_int (2 * secret_chat->in_seq_no + (secret_chat->admin_id != tgl_get_peer_id (tgl_state::instance()->our_id())));
  out_int (2 * secret_chat->out_seq_no + (secret_chat->admin_id == tgl_get_peer_id (tgl_state::instance()->our_id())) - 2);
  out_int (CODE_decrypted_message_service);
  out_long (M->permanent_id.id);

  switch (M->action->type()) {
  case tgl_message_action_type_notify_layer:
    out_int (CODE_decrypted_message_action_notify_layer);
    out_int (std::static_pointer_cast<tgl_message_action_notify_layer>(M->action)->layer);
    break;
  case tgl_message_action_type_set_message_ttl:
    out_int (CODE_decrypted_message_action_set_message_t_t_l);
    out_int (std::static_pointer_cast<tgl_message_action_set_message_ttl>(M->action)->ttl);
    break;
  case tgl_message_action_type_request_key:
  {
    auto action = std::static_pointer_cast<tgl_message_action_request_key>(M->action);
    out_int (CODE_decrypted_message_action_request_key);
    out_long (action->exchange_id);
    out_cstring (reinterpret_cast<char*>(action->g_a.data()), 256);
    break;
  }
  case tgl_message_action_type_accept_key:
  {
    auto action = std::static_pointer_cast<tgl_message_action_accept_key>(M->action);
    out_int (CODE_decrypted_message_action_accept_key);
    out_long (action->exchange_id);
    out_cstring (reinterpret_cast<char*>(action->g_a.data()), 256);
    out_long (action->key_fingerprint);
    break;
  }
  case tgl_message_action_type_commit_key:
  {
    auto action = std::static_pointer_cast<tgl_message_action_commit_key>(M->action);
    out_int (CODE_decrypted_message_action_commit_key);
    out_long (action->exchange_id);
    out_long (action->key_fingerprint);
    break;
  }
  case tgl_message_action_type_abort_key:
  {
    auto action = std::static_pointer_cast<tgl_message_action_abort_key>(M->action);
    out_int (CODE_decrypted_message_action_abort_key);
    out_long (action->exchange_id);
    break;
  }
  case tgl_message_action_type_noop:
    out_int (CODE_decrypted_message_action_noop);
    break;
  case tgl_message_action_type_resend:
  {
    auto action = std::static_pointer_cast<tgl_message_action_resend>(M->action);
    out_int (CODE_decrypted_message_action_resend);
    out_int (action->start_seq_no);
    out_int (action->end_seq_no);
    break;
  }
  default:
    assert (0);
  }
  encr_finish (secret_chat.get());

  auto q = std::make_shared<query_msg_send_encr>(secret_chat, M, callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  tglq_send_query_v2(tgl_state::instance()->DC_working, q);
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

  clear_packet ();
  out_int (CODE_messages_send_encrypted);
  out_int (CODE_input_encrypted_chat);
  out_int (tgl_get_peer_id (M->to_id));
  out_long (secret_chat->access_hash);
  out_long (M->permanent_id.id);
  encr_start ();
  out_int (CODE_decrypted_message_layer);
  out_random (15 + 4 * (rand () % 3));
  out_int (TGL_ENCRYPTED_LAYER);
  out_int (2 * secret_chat->in_seq_no + (secret_chat->admin_id != tgl_get_peer_id (tgl_state::instance()->our_id())));
  out_int (2 * secret_chat->out_seq_no + (secret_chat->admin_id == tgl_get_peer_id (tgl_state::instance()->our_id())) - 2);
  out_int (CODE_decrypted_message);
  out_long (M->permanent_id.id);
  out_int (secret_chat->ttl);
  out_cstring (M->message.c_str(), M->message.size());

  assert(M->media);

  switch (M->media->type()) {
  case tgl_message_media_type_none:
    out_int (CODE_decrypted_message_media_empty);
    break;
  case tgl_message_media_type_geo:
  {
    auto media = std::static_pointer_cast<tgl_message_media_geo>(M->media);
    out_int (CODE_decrypted_message_media_geo_point);
    out_double (media->geo.latitude);
    out_double (media->geo.longitude);
    break;
  }
  default:
    assert (0);
  }
  encr_finish (secret_chat.get());
  
  auto q = std::make_shared<query_msg_send_encr>(secret_chat, M, callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  tglq_send_query_v2(tgl_state::instance()->DC_working, q);
}

class query_mark_read_encr: public query_v2
{
public:
    query_mark_read_encr(
            const std::shared_ptr<tgl_secret_chat>& secret_chat,
            const std::function<void(bool)>& callback)
        : query_v2("read encrypted", TYPE_TO_PARAM(bool))
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
            // FIMXE: delete the secret chat?
            //bl_do_peer_delete (P->id);
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
    clear_packet ();
    out_int (CODE_messages_read_encrypted_history);
    out_int (CODE_input_encrypted_chat);
    out_int (tgl_get_peer_id (secret_chat->id));
    out_long (secret_chat->access_hash);
    out_int (secret_chat->last ? secret_chat->last->date : time (0) - 10);

    auto q = std::make_shared<query_mark_read_encr>(secret_chat, callback);
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    tglq_send_query_v2(tgl_state::instance()->DC_working, q);
}

class query_send_encr_file: public query_v2
{
public:
    query_send_encr_file(
            const std::shared_ptr<tgl_secret_chat>& secret_chat,
            const std::shared_ptr<tgl_message>& message,
            const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback)
        : query_v2("send encrypted (file)", TYPE_TO_PARAM(messages_sent_encrypted_message))
        , m_secret_chat(secret_chat)
        , m_message(message)
        , m_callback(callback)
    { }

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
        if (m_secret_chat && m_secret_chat->state != sc_deleted && error_code == 400) {
            if (error_string == "ENCRYPTION_DECLINED") {
                // FIXME: delete the secret chat?
                //bl_do_peer_delete (tgl_state::instance(), secret_chat->id);
            }
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
  out_int (CODE_messages_send_encrypted_file);
  out_int (CODE_input_encrypted_chat);
  out_int (tgl_get_peer_id (f->to_id));
  std::shared_ptr<tgl_secret_chat> secret_chat = tgl_state::instance()->secret_chat_for_id(f->to_id);
  assert(secret_chat);
  out_long (secret_chat->access_hash);
  long long r;
  tglt_secure_random (reinterpret_cast<unsigned char*>(&r), 8);
  out_long (r);
  encr_start ();
  out_int (CODE_decrypted_message_layer);
  out_random (15 + 4 * (rand () % 3));
  out_int (TGL_ENCRYPTED_LAYER);
  out_int (2 * secret_chat->in_seq_no + (secret_chat->admin_id != tgl_get_peer_id (tgl_state::instance()->our_id())));
  out_int (2 * secret_chat->out_seq_no + (secret_chat->admin_id == tgl_get_peer_id (tgl_state::instance()->our_id())));
  out_int (CODE_decrypted_message);
  out_long (r);
  out_int (secret_chat->ttl);
  out_string ("");
  int *save_ptr = packet_ptr;
  if (f->flags == -1) {
    out_int (CODE_decrypted_message_media_photo);
  } else if ((f->flags & TGLDF_VIDEO)) {
    out_int (CODE_decrypted_message_media_video);
  } else if ((f->flags & TGLDF_AUDIO)) {
    out_int (CODE_decrypted_message_media_audio);
  } else {
    out_int (CODE_decrypted_message_media_document);
  }
  if (f->flags == -1 || !(f->flags & TGLDF_AUDIO)) {
    out_cstring ("", 0);
    out_int (90);
    out_int (90);
  }
  
  if (f->flags == -1) {
    out_int (f->w);
    out_int (f->h);
  } else if (f->flags & TGLDF_VIDEO) {
    out_int (f->duration);
    out_string (tg_mime_by_filename (f->file_name.c_str()));
    out_int (f->w);
    out_int (f->h);
  } else if (f->flags & TGLDF_AUDIO) {
    out_int (f->duration);
    out_string (tg_mime_by_filename (f->file_name.c_str()));
  } else {
    // FIXME: for no '/' sepearator filesystems.
    auto filename = f->file_name;
    auto pos = filename.rfind('/');
    if (pos != std::string::npos) {
        filename = filename.substr(pos + 1);
    }
    out_string (filename.c_str());
    out_string (tg_mime_by_filename (f->file_name.c_str()));
    // document
  }
  
  out_int (f->size);
  out_cstring (reinterpret_cast<const char*>(f->key), 32);
  out_cstring (reinterpret_cast<const char*>(f->init_iv), 32);
 
  int *save_in_ptr = in_ptr;
  int *save_in_end = in_end;

  in_ptr = save_ptr;
  in_end = packet_ptr;

  struct paramed_type decrypted_message_media = TYPE_TO_PARAM(decrypted_message_media);
  auto result = skip_type_any (&decrypted_message_media);
  TGL_ASSERT_UNUSED(result, result >= 0);
  assert (in_ptr == in_end);
  
  in_ptr = save_ptr;
  in_end = packet_ptr;
  
  struct tl_ds_decrypted_message_media *DS_DMM = fetch_ds_type_decrypted_message_media (&decrypted_message_media);
  in_end = save_in_ptr;
  in_ptr = save_in_end;


  int date = time (NULL);


  encr_finish (secret_chat.get());
  if (f->size < (16 << 20)) {
    out_int (CODE_input_encrypted_file_uploaded);
  } else {
    out_int (CODE_input_encrypted_file_big_uploaded);
  }
  out_long (f->id);
  out_int (f->part_num);
  if (f->size < (16 << 20)) {
    out_string ("");
  }

  unsigned char md5[16];
  unsigned char str[64];
  memcpy (str, f->key, 32);
  memcpy (str + 32, f->init_iv, 32);
  TGLC_md5 (str, 64, md5);
  out_int ((*(int *)md5) ^ (*(int *)(md5 + 4)));

  tfree_secure (f->iv, 32);
 
  tgl_peer_id_t from_id = tgl_state::instance()->our_id();
  
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
      
  auto q = std::make_shared<query_send_encr_file>(secret_chat, M, callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  tglq_send_query_v2(tgl_state::instance()->DC_working, q);
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

class query_send_encr_accept: public query_v2
{
public:
    explicit query_send_encr_accept(
            const std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)>& callback)
        : query_v2("send encrypted (chat accept)", TYPE_TO_PARAM(encrypted_chat))
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        std::shared_ptr<tgl_secret_chat> secret_chat = tglf_fetch_alloc_encrypted_chat(
                static_cast<tl_ds_encrypted_chat*>(D));

        if (secret_chat && secret_chat->state == sc_ok) {
            tgl_do_send_encr_chat_layer(secret_chat);
        }

        if (m_callback) {
            m_callback(secret_chat && secret_chat->state == sc_ok, secret_chat);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
#if 0 // FIXME
        tgl_peer_t *P = (tgl_peer_t *)q->extra;
        if (P && P->encr_chat.state != sc_deleted &&  error_code == 400) {
          if (strncmp (error, "ENCRYPTION_DECLINED", 19) == 0) {
            bl_do_peer_delete (P->id);
          }
        }
#endif
        if (m_callback) {
            m_callback(false, nullptr);
        }
        return 0;
    }

private:
    std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)> m_callback;
};

class query_send_encr_request: public query_v2
{
public:
    explicit query_send_encr_request(
            const std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)>& callback)
        : query_v2("send encrypted (chat request)", TYPE_TO_PARAM(encrypted_chat))
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        std::shared_ptr<tgl_secret_chat> secret_chat = tglf_fetch_alloc_encrypted_chat(
                static_cast<tl_ds_encrypted_chat*>(D));

        if (m_callback) {
            m_callback(secret_chat && secret_chat->state == sc_ok, secret_chat);
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

  clear_packet ();
  out_int (CODE_messages_accept_encryption);
  out_int (CODE_input_encrypted_chat);
  out_int (tgl_get_peer_id (secret_chat->id));
  out_long (secret_chat->access_hash);
  
  ensure (TGLC_bn_set_word (g_a, secret_chat->encr_root));
  ensure (TGLC_bn_mod_exp (r, g_a, b, p, tgl_state::instance()->bn_ctx));
  static unsigned char buf[256];
  memset (buf, 0, sizeof (buf));
  TGLC_bn_bn2bin (r, buf + (256 - TGLC_bn_num_bytes (r)));
  out_cstring (reinterpret_cast<const char*>(buf), 256);

  out_long (secret_chat->key_fingerprint());
  TGLC_bn_clear_free (b);
  TGLC_bn_clear_free (g_a);
  TGLC_bn_clear_free (r);

  auto q = std::make_shared<query_send_encr_accept>(callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  tglq_send_query_v2(tgl_state::instance()->DC_working, q);
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

  clear_packet ();
  out_int (CODE_messages_request_encryption);
  
  out_int (CODE_input_user);
  out_int (secret_chat->user_id);
  out_long(secret_chat->access_hash);

  out_int (tgl_get_peer_id (secret_chat->id));
  out_cstring (g_a, 256);
  //write_secret_chat_file ();
  
  TGLC_bn_clear_free (g);
  TGLC_bn_clear_free (p);
  TGLC_bn_clear_free (r);

  auto q = std::make_shared<query_send_encr_request>(callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  tglq_send_query_v2(tgl_state::instance()->DC_working, q);
}

class query_send_encr_discard: public query_v2
{
public:
    query_send_encr_discard(
            const std::shared_ptr<tgl_secret_chat>& secret_chat,
            const std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)>& callback)
        : query_v2("send encrypted (chat discard)", TYPE_TO_PARAM(bool))
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

  clear_packet ();
  out_int (CODE_messages_discard_encryption);
  out_int (tgl_get_peer_id (secret_chat->id));

  auto q = std::make_shared<query_send_encr_discard>(secret_chat, callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  tglq_send_query_v2(tgl_state::instance()->DC_working, q);
}

class query_get_dh_config: public query_v2
{
public:
    query_get_dh_config(const std::shared_ptr<tgl_secret_chat>& secret_chat,
            const std::function<void(const std::shared_ptr<tgl_secret_chat>&,
                    std::array<unsigned char, 256>& random,
                    const std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)>&)>& callback,
            const std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)>& final_callback)
        : query_v2("get dh config", TYPE_TO_PARAM(messages_dh_config))
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

    clear_packet ();
    out_int (CODE_messages_get_dh_config);
    out_int (secret_chat->encr_param_version);
    out_int (256);

    auto q = std::make_shared<query_get_dh_config>(secret_chat, tgl_do_send_accept_encr_chat, callback);
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    tglq_send_query_v2(tgl_state::instance()->DC_working, q);
}

int tgl_do_create_encr_chat_request(const tgl_peer_id_t& user_id, std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)> callback) {
    int t = rand ();
    while (tgl_state::instance()->secret_chat_for_id(TGL_MK_ENCR_CHAT(t))) {
        t = rand ();
    }

    std::shared_ptr<tgl_secret_chat> secret_chat = tgl_state::instance()->ensure_secret_chat(TGL_MK_ENCR_CHAT(t));
    secret_chat->user_id = user_id.peer_id;
    secret_chat->access_hash = user_id.access_hash;
    secret_chat->id.access_hash = user_id.access_hash;

    clear_packet ();
    out_int (CODE_messages_get_dh_config);
    out_int (0);
    out_int (256);

    auto q = std::make_shared<query_get_dh_config>(secret_chat, tgl_do_send_create_encr_chat, callback);
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    tglq_send_query_v2(tgl_state::instance()->DC_working, q);

    return t;
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
