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

#include "queries-encrypted.h"

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

#include "auto/auto.h"
#include "auto/auto-fetch-ds.h"
#include "auto/auto-free-ds.h"
#include "auto/auto-types.h"
#include "auto/constants.h"
#include "crypto/tgl_crypto_aes.h"
#include "crypto/tgl_crypto_md5.h"
#include "mtproto-client.h"
#include "mtproto-common.h"
#include "mtproto-utils.h"
#include "queries.h"
#include "tgl.h"
#include "tgl-log.h"
#include "tools.h"
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
void secret_chat_encryptor::start()
{
    m_encr_base = m_serializer->reserve_i32s(1/*str len*/ + 2/*fingerprint*/ + 4/*msg_key*/ + 1/*len*/);
}

void secret_chat_encryptor::end()
{
    size_t length = m_serializer->i32_size() - (m_encr_base + 8);
    while ((m_serializer->i32_size() - m_encr_base - 3) & 3) {
        int32_t i;
        tglt_secure_random(reinterpret_cast<unsigned char*>(&i), 4);
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
    memcpy(buf, msg_key, 16);
    memcpy(buf + 16, encryption_key, 32);
    TGLC_sha1(buf, 48, sha1a_buffer);

    memcpy(buf, encryption_key + 8, 16);
    memcpy(buf + 16, msg_key, 16);
    memcpy(buf + 32, encryption_key + 12, 16);
    TGLC_sha1(buf, 48, sha1b_buffer);

    memcpy(buf, encryption_key + 16, 32);
    memcpy(buf + 32, msg_key, 16);
    TGLC_sha1(buf, 48, sha1c_buffer);

    memcpy(buf, msg_key, 16);
    memcpy(buf + 16, encryption_key + 24, 32);
    TGLC_sha1(buf, 48, sha1d_buffer);

    unsigned char key[32];
    memset(key, 0, sizeof(key));
    memcpy(key, sha1a_buffer + 0, 8);
    memcpy(key + 8, sha1b_buffer + 8, 12);
    memcpy(key + 20, sha1c_buffer + 4, 12);

    unsigned char iv[32];
    memset(iv, 0, sizeof(iv));
    memcpy(iv, sha1a_buffer + 8, 12);
    memcpy(iv + 12, sha1b_buffer + 0, 8);
    memcpy(iv + 20, sha1c_buffer + 16, 4);
    memcpy(iv + 24, sha1d_buffer + 0, 8);

    TGLC_aes_key aes_key;
    TGLC_aes_set_encrypt_key(key, 256, &aes_key);
    TGLC_aes_ige_encrypt(reinterpret_cast<const unsigned char*>(encr_ptr), reinterpret_cast<unsigned char*>(encrypted_data), 4 * (encr_end - encr_ptr), &aes_key, iv, 1);
    memset(&aes_key, 0, sizeof(aes_key));
}

static void do_set_dh_params(const std::shared_ptr<tgl_secret_chat>& secret_chat, int root, unsigned char prime[], int version)
{
    secret_chat->encr_root = root;
    secret_chat->set_encr_prime(prime, 256);
    secret_chat->encr_param_version = version;

    auto res = tglmp_check_DH_params(secret_chat->encr_prime_bn(), secret_chat->encr_root);
    TGL_ASSERT_UNUSED(res, res >= 0);
}

static bool create_keys_end(const std::shared_ptr<tgl_secret_chat>& secret_chat);

void tgl_secret_chat_deleted(const std::shared_ptr<tgl_secret_chat>& secret_chat)
{
     tgl_update_secret_chat(secret_chat,
         nullptr,
         nullptr,
         nullptr,
         nullptr,
         nullptr,
         nullptr,
         tgl_secret_chat_state::deleted,
         nullptr,
         nullptr,
         nullptr);
    tgl_state::instance()->callback()->secret_chat_update(secret_chat);
}

void tgl_update_secret_chat(const std::shared_ptr<tgl_secret_chat>& secret_chat,
        const int64_t* access_hash,
        const int32_t* date,
        const int32_t* admin,
        const int32_t* user_id,
        const unsigned char* key,
        const unsigned char* g_key,
        const tgl_secret_chat_state& state,
        const int32_t* ttl,
        const int32_t* layer,
        const int32_t* in_seq_no)
{
    assert(secret_chat);

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

    if (g_key) {
        secret_chat->g_key.resize(256);
        std::copy(g_key, g_key + 256, secret_chat->g_key.begin());
    }

    if (key) {
        secret_chat->set_key(key);
    }

    if (secret_chat->state == tgl_secret_chat_state::waiting && state == tgl_secret_chat_state::ok) {
        if (create_keys_end(secret_chat)) {
            secret_chat->state = state;
        } else {
            secret_chat->state = tgl_secret_chat_state::deleted;
        }
    } else {
        secret_chat->state = state;
    }
}

/* }}} */

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
        tgl_state::instance()->callback()->message_id_update(m_message->permanent_id, m_message->permanent_id, m_secret_chat->out_seq_no, m_message->to_id);
        if (m_callback) {
            m_callback(true, m_message);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        if (m_secret_chat && m_secret_chat->state != tgl_secret_chat_state::deleted && error_code == 400 && error_string == "ENCRYPTION_DECLINED") {
            tgl_secret_chat_deleted(m_secret_chat);
        }

        if (m_callback) {
            m_callback(false, m_message);
        }

        if (m_message) {
            //bl_do_message_delete(&M->permanent_id);
            // FIXME: is this correct?
            tgl_state::instance()->callback()->message_deleted(m_message->permanent_id);
        }
        return 0;
    }

private:
    std::shared_ptr<tgl_secret_chat> m_secret_chat;
    std::shared_ptr<tgl_message> m_message;
    std::function<void(bool, const std::shared_ptr<tgl_message>&)> m_callback;
};

static void tgl_do_send_encr_msg_action(const std::shared_ptr<tgl_secret_chat>& secret_chat,
        const std::shared_ptr<tgl_message>& M,
        const std::function<void(bool, const std::shared_ptr<tgl_message>& M)>& callback)
{
    if (!secret_chat || secret_chat->state != tgl_secret_chat_state::ok) {
        TGL_WARNING("unknown encrypted chat");
        if (callback) {
            callback(false, nullptr);
        }
        return;
    }

    assert(M->action);

    auto q = std::make_shared<query_msg_send_encr>(secret_chat, M, callback);
    secret_chat_encryptor encryptor(secret_chat, q->serializer());
    q->out_i32(CODE_messages_send_encrypted_service);
    q->out_i32(CODE_input_encrypted_chat);
    q->out_i32(secret_chat->id.peer_id);
    q->out_i64(secret_chat->id.access_hash);
    q->out_i64(M->permanent_id);
    encryptor.start();
    q->out_i32(CODE_decrypted_message_layer);
    q->out_random(15 + 4 * (tgl_random<int>() % 3));
    q->out_i32(TGL_ENCRYPTED_LAYER);
    q->out_i32(2 * secret_chat->in_seq_no + (secret_chat->admin_id != tgl_state::instance()->our_id().peer_id));
    q->out_i32(2 * secret_chat->out_seq_no + (secret_chat->admin_id == tgl_state::instance()->our_id().peer_id) - 2);
    q->out_i32(CODE_decrypted_message_service);
    q->out_i64(M->permanent_id);

    switch (M->action->type()) {
    case tgl_message_action_type::notify_layer:
        q->out_i32(CODE_decrypted_message_action_notify_layer);
        q->out_i32(std::static_pointer_cast<tgl_message_action_notify_layer>(M->action)->layer);
        break;
    case tgl_message_action_type::set_message_ttl:
        q->out_i32(CODE_decrypted_message_action_set_message_ttl);
        q->out_i32(std::static_pointer_cast<tgl_message_action_set_message_ttl>(M->action)->ttl);
        break;
    case tgl_message_action_type::request_key:
    {
        auto action = std::static_pointer_cast<tgl_message_action_request_key>(M->action);
        q->out_i32(CODE_decrypted_message_action_request_key);
        q->out_i64(action->exchange_id);
        q->out_string(reinterpret_cast<char*>(action->g_a.data()), 256);
        break;
    }
    case tgl_message_action_type::accept_key:
    {
        auto action = std::static_pointer_cast<tgl_message_action_accept_key>(M->action);
        q->out_i32(CODE_decrypted_message_action_accept_key);
        q->out_i64(action->exchange_id);
        q->out_string(reinterpret_cast<char*>(action->g_a.data()), 256);
        q->out_i64(action->key_fingerprint);
        break;
    }
    case tgl_message_action_type::commit_key:
    {
        auto action = std::static_pointer_cast<tgl_message_action_commit_key>(M->action);
        q->out_i32(CODE_decrypted_message_action_commit_key);
        q->out_i64(action->exchange_id);
        q->out_i64(action->key_fingerprint);
        break;
    }
    case tgl_message_action_type::abort_key:
    {
        auto action = std::static_pointer_cast<tgl_message_action_abort_key>(M->action);
        q->out_i32(CODE_decrypted_message_action_abort_key);
        q->out_i64(action->exchange_id);
        break;
    }
    case tgl_message_action_type::noop:
        q->out_i32(CODE_decrypted_message_action_noop);
        break;
    case tgl_message_action_type::resend:
    {
        auto action = std::static_pointer_cast<tgl_message_action_resend>(M->action);
        q->out_i32(CODE_decrypted_message_action_resend);
        q->out_i32(action->start_seq_no);
        q->out_i32(action->end_seq_no);
        break;
    }
    case tgl_message_action_type::delete_messages:
    {
        auto action = std::static_pointer_cast<tgl_message_action_delete_messages>(M->action);
        q->out_i32 (CODE_decrypted_message_action_delete_messages);
        q->out_i32(CODE_vector);
        q->out_i32(action->msg_ids.size());
        for (auto id : action->msg_ids) {
            q->out_i64(id);
        }
        break;
    }
    default:
        assert(false);
    }
    encryptor.end();
    q->execute(tgl_state::instance()->working_dc());
}

void tgl_do_send_encr_msg(const std::shared_ptr<tgl_secret_chat>& secret_chat,
        const std::shared_ptr<tgl_message>& M,
        const std::function<void(bool, const std::shared_ptr<tgl_message>& M)>& callback)
{
    if (M->is_service()) {
        if (!M->action) {
            return;
        }
        tgl_do_send_encr_msg_action(secret_chat, M, callback);
        return;
    }

    if (!secret_chat || secret_chat->state != tgl_secret_chat_state::ok) {
        TGL_WARNING("unknown encrypted chat");
        if (callback) {
            callback(false, M);
        }
        return;
    }

    auto q = std::make_shared<query_msg_send_encr>(secret_chat, M, callback);
    secret_chat_encryptor encryptor(secret_chat, q->serializer());
    q->out_i32(CODE_messages_send_encrypted);
    q->out_i32(CODE_input_encrypted_chat);
    q->out_i32(secret_chat->id.peer_id);
    q->out_i64(secret_chat->access_hash);
    q->out_i64(M->permanent_id);
    encryptor.start();
    q->out_i32(CODE_decrypted_message_layer);
    q->out_random(15 + 4 * (tgl_random<int>() % 3));
    q->out_i32(TGL_ENCRYPTED_LAYER);
    q->out_i32(2 * secret_chat->in_seq_no + (secret_chat->admin_id != tgl_state::instance()->our_id().peer_id));
    q->out_i32(2 * secret_chat->out_seq_no + (secret_chat->admin_id == tgl_state::instance()->our_id().peer_id) - 2);
    q->out_i32(CODE_decrypted_message);
    q->out_i64(M->permanent_id);
    q->out_i32(secret_chat->ttl);
    q->out_string(M->message.c_str(), M->message.size());

    assert(M->media);

    switch (M->media->type()) {
    case tgl_message_media_type::none:
        q->out_i32(CODE_decrypted_message_media_empty);
        break;
    case tgl_message_media_type::geo:
    {
        auto media = std::static_pointer_cast<tgl_message_media_geo>(M->media);
        q->out_i32(CODE_decrypted_message_media_geo_point);
        q->out_double(media->geo.latitude);
        q->out_double(media->geo.longitude);
        break;
    }
    default:
        assert(false);
    }
    encryptor.end();

    q->execute(tgl_state::instance()->working_dc());
}

static void tgl_do_send_encr_action(const std::shared_ptr<tgl_secret_chat>& secret_chat,
        const tl_ds_decrypted_message_action& action, const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback)
{
    int64_t date = tgl_get_system_time();

    int64_t message_id;
    tglt_secure_random(reinterpret_cast<unsigned char*>(&message_id), 8);

    tgl_peer_id_t from_id = tgl_state::instance()->our_id();
    std::shared_ptr<tgl_message> M = tglm_create_encr_message(secret_chat,
            message_id,
            from_id,
            secret_chat->id,
            &date,
            std::string(),
            nullptr,
            &action,
            nullptr,
            true);
    M->set_pending(true).set_unread(true);
    tgl_state::instance()->callback()->new_messages({M});
    tgl_do_send_encr_msg(secret_chat, M, callback);
}

void tgl_do_send_encr_chat_layer(const std::shared_ptr<tgl_secret_chat>& secret_chat)
{
    struct tl_ds_decrypted_message_action action;
    memset(&action, 0, sizeof(action));
    action.magic = CODE_decrypted_message_action_notify_layer;
    int layer = TGL_ENCRYPTED_LAYER;
    action.layer = &layer;

    tgl_do_send_encr_action(secret_chat, action, nullptr);
}

void tgl_do_send_encr_chat_request_resend(const std::shared_ptr<tgl_secret_chat>& secret_chat,
        int start_seq_no, int end_seq_no)
{
    struct tl_ds_decrypted_message_action action;
    action.magic = CODE_decrypted_message_action_resend;
    action.start_seq_no = &start_seq_no;
    action.end_seq_no = &end_seq_no;

    tgl_do_send_encr_action(secret_chat, action, nullptr);
}

void tgl_do_set_encr_chat_ttl(const std::shared_ptr<tgl_secret_chat>& secret_chat, int ttl)
{
    struct tl_ds_decrypted_message_action action;
    action.magic = CODE_decrypted_message_action_set_message_ttl;
    action.ttl_seconds = &ttl;

    tgl_do_send_encr_action(secret_chat, action, nullptr);
}

void tgl_do_messages_delete_encr(const std::shared_ptr<tgl_secret_chat>& secret_chat, int64_t msg_id,
        const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback)
{
    struct tl_ds_decrypted_message_action action;
    action.magic = CODE_decrypted_message_action_delete_messages;

    std::remove_pointer<decltype(action.random_ids)>::type ids;

    int count = 1;
    ids.cnt = &count;
    //int64_t *ids_array = (int64_t *)malloc(sizeof(int64_t));
    //ids_array[0] = msg_id;
    int64_t *zahl = &msg_id;
    //int64_t ids_array[1] = {msg_id};
    ids.data = &zahl;

    action.random_ids = &ids;
    tgl_do_send_encr_action(secret_chat, action, callback);
}

class query_mark_read_encr: public query
{
public:
    query_mark_read_encr(int32_t max_time,
            const std::shared_ptr<tgl_secret_chat>& secret_chat,
            const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback)
        : query("read encrypted", TYPE_TO_PARAM(bool))
        , m_max_time(max_time)
        , m_secret_chat(secret_chat)
        , m_callback(callback)
    { }

    virtual void on_answer(void*) override
    {
        if (tgl_state::instance()->callback()) {
            tgl_state::instance()->callback()->messages_mark_read_in(tgl_peer_id_t::from_input_peer(m_secret_chat->id), m_max_time);
        }
        if (m_callback) {
            m_callback(true, nullptr);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        if (m_secret_chat->state != tgl_secret_chat_state::deleted && error_code == 400 && error_string == "ENCRYPTION_DECLINED") {
            tgl_secret_chat_deleted(m_secret_chat);
        }

        if (m_callback) {
            m_callback(false, nullptr);
        }

        return 0;
    }

private:
    int32_t m_max_time;
    std::shared_ptr<tgl_secret_chat> m_secret_chat;
    std::function<void(bool, const std::shared_ptr<tgl_message>&)> m_callback;
};

void tgl_do_messages_mark_read_encr(const std::shared_ptr<tgl_secret_chat>& secret_chat, int32_t max_time,
        const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback)
{
    auto q = std::make_shared<query_mark_read_encr>(max_time, secret_chat, callback);
    q->out_i32(CODE_messages_read_encrypted_history);
    q->out_i32(CODE_input_encrypted_chat);
    q->out_i32(secret_chat->id.peer_id);
    q->out_i64(secret_chat->access_hash);
    q->out_i32(max_time); // FIXME
    q->execute(tgl_state::instance()->working_dc());
}

void tgl_do_send_location_encr(const tgl_input_peer_t& to_id, double latitude, double longitude,
        const std::function<void(bool success, const std::shared_ptr<tgl_message>& M)>& callback)
{
    struct tl_ds_decrypted_message_media TDSM;
    memset(&TDSM, 0, sizeof(TDSM));
    TDSM.magic = CODE_decrypted_message_media_geo_point;
    TDSM.latitude = static_cast<double*>(malloc(sizeof(double)));
    *TDSM.latitude = latitude;
    TDSM.longitude = static_cast<double*>(malloc(sizeof(double)));
    *TDSM.longitude = longitude;

    int64_t date = tgl_get_system_time();

    tgl_peer_id_t from_id = tgl_state::instance()->our_id();

    std::shared_ptr<tgl_secret_chat> secret_chat = tgl_state::instance()->secret_chat_for_id(to_id);
    assert(secret_chat);

    int64_t message_id;
    tglt_secure_random(reinterpret_cast<unsigned char*>(&message_id), 8);
    std::shared_ptr<tgl_message> M = tglm_create_encr_message(secret_chat,
          message_id,
          from_id,
          to_id,
          &date,
          std::string(),
          &TDSM,
          nullptr,
          nullptr,
          true);
    M->set_unread(true).set_pending(true);

    free(TDSM.latitude);
    free(TDSM.longitude);

    tgl_state::instance()->callback()->new_messages({M});
    tgl_do_send_encr_msg(secret_chat, M, callback);
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

        if (secret_chat && secret_chat->state == tgl_secret_chat_state::ok) {
            tgl_do_send_encr_chat_layer(secret_chat);
            tgl_state::instance()->callback()->secret_chat_update(secret_chat);
        }

        if (secret_chat) {
            assert(m_secret_chat == secret_chat);
        }

        if (m_callback) {
            m_callback(secret_chat && secret_chat->state == tgl_secret_chat_state::ok, secret_chat);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        if (m_secret_chat && m_secret_chat->state != tgl_secret_chat_state::deleted && error_code == 400 && error_string == "ENCRYPTION_DECLINED") {
            tgl_secret_chat_deleted(m_secret_chat);
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
        tgl_state::instance()->callback()->secret_chat_update(secret_chat);

        if (m_callback) {
            m_callback(secret_chat && secret_chat->state != tgl_secret_chat_state::deleted, secret_chat);
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
    bool ok = false;
    const int* key = reinterpret_cast<const int*>(secret_chat->key());
    for (int i = 0; i < 64; i++) {
        if (key[i]) {
            ok = true;
            break;
        }
    }
    if (ok) {
        // Already generated key for this chat
        if (callback) {
            callback(true, secret_chat);
        }
        return;
    }

    assert(!secret_chat->g_key.empty());
    assert(tgl_state::instance()->bn_ctx());
    unsigned char random_here[256];
    tglt_secure_random(random_here, 256);
    for (int i = 0; i < 256; i++) {
        random[i] ^= random_here[i];
    }
    std::unique_ptr<TGLC_bn, TGLC_bn_clear_deleter> b(TGLC_bn_bin2bn(random.data(), 256, 0));
    std::unique_ptr<TGLC_bn, TGLC_bn_clear_deleter> g_a(TGLC_bn_bin2bn(secret_chat->g_key.data(), 256, 0));
    if (tglmp_check_g_a(secret_chat->encr_prime_bn(), g_a.get()) < 0) {
        if (callback) {
            callback(false, secret_chat);
        }
        tgl_secret_chat_deleted(secret_chat);
        return;
    }

    TGLC_bn* p = secret_chat->encr_prime_bn();
    std::unique_ptr<TGLC_bn, TGLC_bn_clear_deleter> r(TGLC_bn_new());
    check_crypto_result(TGLC_bn_mod_exp(r.get(), g_a.get(), b.get(), p, tgl_state::instance()->bn_ctx()));
    unsigned char buffer[256];
    memset(buffer, 0, sizeof(buffer));
    TGLC_bn_bn2bin(r.get(), buffer + (256 - TGLC_bn_num_bytes(r.get())));

    tgl_update_secret_chat(secret_chat,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            buffer,
            nullptr,
            tgl_secret_chat_state::ok,
            nullptr,
            nullptr,
            nullptr);

    memset(buffer, 0, sizeof(buffer));
    check_crypto_result(TGLC_bn_set_word(g_a.get(), secret_chat->encr_root));
    check_crypto_result(TGLC_bn_mod_exp(r.get(), g_a.get(), b.get(), p, tgl_state::instance()->bn_ctx()));
    TGLC_bn_bn2bin(r.get(), buffer + (256 - TGLC_bn_num_bytes(r.get())));

    auto q = std::make_shared<query_send_encr_accept>(secret_chat, callback);
    q->out_i32(CODE_messages_accept_encryption);
    q->out_i32(CODE_input_encrypted_chat);
    q->out_i32(secret_chat->id.peer_id);
    q->out_i64(secret_chat->access_hash);
    q->out_string(reinterpret_cast<const char*>(buffer), 256);
    q->out_i64(secret_chat->key_fingerprint());
    q->execute(tgl_state::instance()->working_dc());
}

static bool create_keys_end(const std::shared_ptr<tgl_secret_chat>& secret_chat)
{
    assert(!secret_chat->encr_prime().empty());
    if (secret_chat->encr_prime().empty()) {
        return false;
    }

    std::unique_ptr<TGLC_bn, TGLC_bn_clear_deleter> g_b(TGLC_bn_bin2bn(secret_chat->g_key.data(), 256, 0));
    if (tglmp_check_g_a(secret_chat->encr_prime_bn(), g_b.get()) < 0) {
        return false;
    }

    TGLC_bn* p = secret_chat->encr_prime_bn();
    std::unique_ptr<TGLC_bn, TGLC_bn_clear_deleter> r(TGLC_bn_new());
    std::unique_ptr<TGLC_bn, TGLC_bn_clear_deleter> a(TGLC_bn_bin2bn(secret_chat->key(), tgl_secret_chat::key_size(), 0));
    check_crypto_result(TGLC_bn_mod_exp(r.get(), g_b.get(), a.get(), p, tgl_state::instance()->bn_ctx()));

    std::vector<unsigned char> key(tgl_secret_chat::key_size(), 0);

    TGLC_bn_bn2bin(r.get(), (key.data() + (tgl_secret_chat::key_size() - TGLC_bn_num_bytes(r.get()))));
    secret_chat->set_key(key.data());

    if (secret_chat->key_fingerprint() != secret_chat->temp_key_fingerprint) {
        TGL_WARNING("key fingerprint mismatch (my 0x" << std::hex
                << (uint64_t)secret_chat->key_fingerprint()
                << "x 0x" << (uint64_t)secret_chat->temp_key_fingerprint << "x)");
        return false;
    }
    secret_chat->temp_key_fingerprint = 0;
    return true;
}

static void tgl_do_send_create_encr_chat(const std::shared_ptr<tgl_secret_chat>& secret_chat,
        std::array<unsigned char, 256>& random,
        std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)> callback)
{
    unsigned char random_here[256];
    tglt_secure_random(random_here, 256);
    for (int i = 0; i < 256; i++) {
        random[i] ^= random_here[i];
    }

    std::unique_ptr<TGLC_bn, TGLC_bn_clear_deleter> a(TGLC_bn_bin2bn(random.data(), 256, 0));
    TGLC_bn* p = secret_chat->encr_prime_bn();

    std::unique_ptr<TGLC_bn, TGLC_bn_clear_deleter> g(TGLC_bn_new());
    check_crypto_result(TGLC_bn_set_word(g.get(), secret_chat->encr_root));

    std::unique_ptr<TGLC_bn, TGLC_bn_clear_deleter> r(TGLC_bn_new());

    check_crypto_result(TGLC_bn_mod_exp(r.get(), g.get(), a.get(), p, tgl_state::instance()->bn_ctx()));

    char g_a[256];
    memset(g_a, 0, sizeof(g_a));

    TGLC_bn_bn2bin(r.get(), reinterpret_cast<unsigned char*>(g_a + (256 - TGLC_bn_num_bytes(r.get()))));

    int our_id = tgl_state::instance()->our_id().peer_id;
    tgl_update_secret_chat(secret_chat,
          nullptr,
          nullptr,
          &our_id,
          nullptr,
          random.data(),
          nullptr,
          tgl_secret_chat_state::waiting,
          nullptr,
          nullptr,
          nullptr);
    tgl_state::instance()->callback()->secret_chat_update(secret_chat);

    auto q = std::make_shared<query_send_encr_request>(callback);
    q->out_i32(CODE_messages_request_encryption);
    q->out_i32(CODE_input_user);
    q->out_i32(secret_chat->user_id);
    q->out_i64(secret_chat->access_hash);
    q->out_i32(secret_chat->id.peer_id);
    q->out_string(g_a, sizeof(g_a));
    q->execute(tgl_state::instance()->working_dc());
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

void tgl_do_discard_secret_chat(const std::shared_ptr<tgl_secret_chat>& secret_chat,
        const std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)>& callback)
{
    assert(secret_chat);

    if (secret_chat->state == tgl_secret_chat_state::deleted || secret_chat->state == tgl_secret_chat_state::none) {
        if (callback) {
            callback(false, secret_chat);
        }
        return;
    }

    auto q = std::make_shared<query_send_encr_discard>(secret_chat, callback);
    q->out_i32(CODE_messages_discard_encryption);
    q->out_i32(secret_chat->id.peer_id);

    q->execute(tgl_state::instance()->working_dc());
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

        bool fail = false;
        if (DS_MDC->magic == CODE_messages_dh_config) {
            if (DS_MDC->p->len == 256) {
                do_set_dh_params(m_secret_chat, DS_LVAL(DS_MDC->g),
                        reinterpret_cast<unsigned char*>(DS_MDC->p->data), DS_LVAL(DS_MDC->version));
            } else {
                TGL_WARNING("the prime got from the server is not of size 256");
                fail = true;
            }
        } else if (DS_MDC->magic == CODE_messages_dh_config_not_modified) {
            TGL_NOTICE("secret chat dh config version not modified");
            if (m_secret_chat->encr_param_version != DS_LVAL(DS_MDC->version)) {
                TGL_WARNING("encryption parameter versions mismatch");
                fail = true;
            }
        } else {
            TGL_WARNING("the server sent us something wrong");
            fail = true;
        }

        if (DS_MDC->random->len != 256) {
            fail = true;
        }

        if (fail) {
            tgl_secret_chat_deleted(m_secret_chat);
            if (m_final_callback) {
                m_final_callback(false, m_secret_chat);
            }
            return;
        }

        if (m_callback) {
            std::array<unsigned char, 256> random;
            memcpy(random.data(), DS_MDC->random->data, 256);
            m_callback(m_secret_chat, random, m_final_callback);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        tgl_secret_chat_deleted(m_secret_chat);
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

void tgl_do_accept_encr_chat_request(const std::shared_ptr<tgl_secret_chat>& secret_chat,
        const std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)>& callback)
{
    if (secret_chat->state != tgl_secret_chat_state::request) {
        if (callback) {
            callback(false, secret_chat);
        }
        return;
    }
    assert(secret_chat->state == tgl_secret_chat_state::request);

    auto q = std::make_shared<query_get_dh_config>(secret_chat, tgl_do_send_accept_encr_chat, callback);
    q->out_i32(CODE_messages_get_dh_config);
    q->out_i32(secret_chat->encr_param_version);
    q->out_i32(256);
    q->execute(tgl_state::instance()->working_dc());
}

/* {{{ Create secret chat */

void tgl_do_create_secret_chat(const tgl_input_peer_t& user_id, int32_t new_secret_chat_id,
        const std::function<void(bool success, const std::shared_ptr<tgl_secret_chat>& E)>& callback)
{
    std::shared_ptr<tgl_secret_chat> secret_chat = tgl_state::instance()->create_secret_chat(new_secret_chat_id);
    secret_chat->user_id = user_id.peer_id;
    secret_chat->access_hash = user_id.access_hash;
    secret_chat->id.access_hash = user_id.access_hash;

    auto q = std::make_shared<query_get_dh_config>(secret_chat, tgl_do_send_create_encr_chat, callback);
    q->out_i32(CODE_messages_get_dh_config);
    q->out_i32(0);
    q->out_i32(256);
    q->execute(tgl_state::instance()->working_dc());
}

void tgl_do_request_exchange(const std::shared_ptr<tgl_secret_chat>&)
{
    assert(0);
    exit(2);
}

void tgl_do_accept_exchange(const std::shared_ptr<tgl_secret_chat>&,
        int64_t exchange_id, const std::vector<unsigned char>& ga)
{
    assert(0);
    exit(2);
}

void tgl_do_confirm_exchange(const std::shared_ptr<tgl_secret_chat>&, int sen_nop)
{
    assert(0);
    exit(2);
}

void tgl_do_commit_exchange(const std::shared_ptr<tgl_secret_chat>&, const std::vector<unsigned char>& gb)
{
    assert(0);
    exit(2);
}

void tgl_do_abort_exchange(const std::shared_ptr<tgl_secret_chat>&)
{
    assert(0);
    exit(2);
}

/* }}} */
