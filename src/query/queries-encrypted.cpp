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

#include "auto/auto.h"
#include "auto/auto-fetch-ds.h"
#include "auto/auto-free-ds.h"
#include "auto/auto-types.h"
#include "auto/constants.h"
#include "crypto/tgl_crypto_aes.h"
#include "crypto/tgl_crypto_bn.h"
#include "crypto/tgl_crypto_md5.h"
#include "crypto/tgl_crypto_sha.h"
#include "mtproto_client.h"
#include "mtproto-common.h"
#include "mtproto-utils.h"
#include "queries.h"
#include "query_messages_send_encrypted_action.h"
#include "query_messages_send_encrypted_base.h"
#include "query_messages_send_encrypted_message.h"
#include "tgl_secret_chat_private.h"
#include "tgl/tgl.h"
#include "tgl/tgl_log.h"
#include "tgl/tgl_secure_random.h"
#include "tgl/tgl_update_callback.h"
#include "tools.h"

#include <algorithm>
#include <array>
#include <errno.h>
#include <fcntl.h>
#include <memory.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifndef WIN32
#include <sys/utsname.h>
#endif

void tgl_do_set_encr_chat_ttl(const std::shared_ptr<tgl_secret_chat>& secret_chat, int ttl)
{
    struct tl_ds_decrypted_message_action action;
    action.magic = CODE_decrypted_message_action_set_message_ttl;
    action.ttl_seconds = &ttl;

    secret_chat->private_facet()->send_action(action, nullptr);
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

        if (secret_chat && secret_chat->state() == tgl_secret_chat_state::ok) {
            secret_chat->private_facet()->send_layer();
        }

        if (secret_chat) {
            assert(m_secret_chat == secret_chat);
        }

        if (m_callback) {
            m_callback(secret_chat && secret_chat->state() == tgl_secret_chat_state::ok, secret_chat);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        if (m_secret_chat && m_secret_chat->state() != tgl_secret_chat_state::deleted && error_code == 400 && error_string == "ENCRYPTION_DECLINED") {
            m_secret_chat->private_facet()->set_deleted();
        }

        if (m_callback) {
            m_callback(false, m_secret_chat);
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
    query_send_encr_request(const std::shared_ptr<tgl_secret_chat>& secret_chat,
            const std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)>& callback)
        : query("send encrypted (chat request)", TYPE_TO_PARAM(encrypted_chat))
        , m_secret_chat(secret_chat)
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        std::shared_ptr<tgl_secret_chat> secret_chat = tglf_fetch_alloc_encrypted_chat(
                static_cast<tl_ds_encrypted_chat*>(D));
        tgl_state::instance()->callback()->secret_chat_update(secret_chat);

        if (m_callback) {
            m_callback(secret_chat && secret_chat->state() != tgl_secret_chat_state::deleted, secret_chat);
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

    assert(!secret_chat->g_key().empty());
    assert(tgl_state::instance()->bn_ctx()->ctx);
    unsigned char random_here[256];
    tgl_secure_random(random_here, 256);
    for (int i = 0; i < 256; i++) {
        random[i] ^= random_here[i];
    }
    std::unique_ptr<TGLC_bn, TGLC_bn_clear_deleter> b(TGLC_bn_bin2bn(random.data(), 256, 0));
    std::unique_ptr<TGLC_bn, TGLC_bn_clear_deleter> g_a(TGLC_bn_bin2bn(secret_chat->g_key().data(), 256, 0));
    if (tglmp_check_g_a(secret_chat->private_facet()->encr_prime_bn()->bn, g_a.get()) < 0) {
        if (callback) {
            callback(false, secret_chat);
        }
        secret_chat->private_facet()->set_deleted();
        return;
    }

    TGLC_bn* p = secret_chat->private_facet()->encr_prime_bn()->bn;
    std::unique_ptr<TGLC_bn, TGLC_bn_clear_deleter> r(TGLC_bn_new());
    check_crypto_result(TGLC_bn_mod_exp(r.get(), g_a.get(), b.get(), p, tgl_state::instance()->bn_ctx()->ctx));
    unsigned char buffer[256];
    memset(buffer, 0, sizeof(buffer));
    TGLC_bn_bn2bin(r.get(), buffer + (256 - TGLC_bn_num_bytes(r.get())));

    secret_chat->private_facet()->set_key(buffer);
    secret_chat->private_facet()->set_state(tgl_secret_chat_state::ok);

    memset(buffer, 0, sizeof(buffer));
    check_crypto_result(TGLC_bn_set_word(g_a.get(), secret_chat->encr_root()));
    check_crypto_result(TGLC_bn_mod_exp(r.get(), g_a.get(), b.get(), p, tgl_state::instance()->bn_ctx()->ctx));
    TGLC_bn_bn2bin(r.get(), buffer + (256 - TGLC_bn_num_bytes(r.get())));

    auto q = std::make_shared<query_send_encr_accept>(secret_chat, callback);
    q->out_i32(CODE_messages_accept_encryption);
    q->out_i32(CODE_input_encrypted_chat);
    q->out_i32(secret_chat->id().peer_id);
    q->out_i64(secret_chat->id().access_hash);
    q->out_string(reinterpret_cast<const char*>(buffer), 256);
    q->out_i64(secret_chat->key_fingerprint());
    q->execute(tgl_state::instance()->active_client());
}

static void tgl_do_send_create_encr_chat(const tgl_input_peer_t& user_id,
        const std::shared_ptr<tgl_secret_chat>& secret_chat,
        std::array<unsigned char, 256>& random,
        std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)> callback)
{
    unsigned char random_here[256];
    tgl_secure_random(random_here, 256);
    for (int i = 0; i < 256; i++) {
        random[i] ^= random_here[i];
    }

    std::unique_ptr<TGLC_bn, TGLC_bn_clear_deleter> a(TGLC_bn_bin2bn(random.data(), 256, 0));
    TGLC_bn* p = secret_chat->private_facet()->encr_prime_bn()->bn;

    std::unique_ptr<TGLC_bn, TGLC_bn_clear_deleter> g(TGLC_bn_new());
    check_crypto_result(TGLC_bn_set_word(g.get(), secret_chat->encr_root()));

    std::unique_ptr<TGLC_bn, TGLC_bn_clear_deleter> r(TGLC_bn_new());

    check_crypto_result(TGLC_bn_mod_exp(r.get(), g.get(), a.get(), p, tgl_state::instance()->bn_ctx()->ctx));

    char g_a[256];
    memset(g_a, 0, sizeof(g_a));

    TGLC_bn_bn2bin(r.get(), reinterpret_cast<unsigned char*>(g_a + (256 - TGLC_bn_num_bytes(r.get()))));

    secret_chat->private_facet()->set_admin_id(tgl_state::instance()->our_id().peer_id);
    secret_chat->private_facet()->set_key(random.data());
    secret_chat->private_facet()->set_state(tgl_secret_chat_state::waiting);
    tgl_state::instance()->callback()->secret_chat_update(secret_chat);

    auto q = std::make_shared<query_send_encr_request>(secret_chat, callback);
    q->out_i32(CODE_messages_request_encryption);
    q->out_i32(CODE_input_user);
    q->out_i32(user_id.peer_id);
    q->out_i64(user_id.access_hash);
    q->out_i32(secret_chat->id().peer_id);
    q->out_string(g_a, sizeof(g_a));
    q->execute(tgl_state::instance()->active_client());
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

    if (secret_chat->state() == tgl_secret_chat_state::deleted || secret_chat->state() == tgl_secret_chat_state::none) {
        if (callback) {
            callback(false, secret_chat);
        }
        return;
    }

    auto q = std::make_shared<query_send_encr_discard>(secret_chat, callback);
    q->out_i32(CODE_messages_discard_encryption);
    q->out_i32(secret_chat->id().peer_id);

    q->execute(tgl_state::instance()->active_client());
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
                m_secret_chat->private_facet()->set_dh_params(DS_LVAL(DS_MDC->g),
                        reinterpret_cast<unsigned char*>(DS_MDC->p->data), DS_LVAL(DS_MDC->version));
            } else {
                TGL_WARNING("the prime got from the server is not of size 256");
                fail = true;
            }
        } else if (DS_MDC->magic == CODE_messages_dh_config_not_modified) {
            TGL_NOTICE("secret chat dh config version not modified");
            if (m_secret_chat->encr_param_version() != DS_LVAL(DS_MDC->version)) {
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
            m_secret_chat->private_facet()->set_deleted();
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
        m_secret_chat->private_facet()->set_deleted();
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
    if (secret_chat->state() != tgl_secret_chat_state::request) {
        if (callback) {
            callback(false, secret_chat);
        }
        return;
    }
    assert(secret_chat->state() == tgl_secret_chat_state::request);

    auto q = std::make_shared<query_get_dh_config>(secret_chat, tgl_do_send_accept_encr_chat, callback);
    q->out_i32(CODE_messages_get_dh_config);
    q->out_i32(secret_chat->encr_param_version());
    q->out_i32(256);
    q->execute(tgl_state::instance()->active_client());
}

/* {{{ Create secret chat */

void tgl_do_create_secret_chat(const tgl_input_peer_t& user_id, int32_t new_secret_chat_id,
        const std::function<void(bool success, const std::shared_ptr<tgl_secret_chat>&)>& callback)
{
    std::shared_ptr<tgl_secret_chat> secret_chat = tgl_state::instance()->create_secret_chat(
            tgl_input_peer_t(tgl_peer_type::enc_chat, new_secret_chat_id, 0), user_id.peer_id);

    if (!secret_chat) {
        if (callback) {
            callback(false, nullptr);
        }
    }

    auto q = std::make_shared<query_get_dh_config>(secret_chat,
            std::bind(&tgl_do_send_create_encr_chat, user_id, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3), callback);
    q->out_i32(CODE_messages_get_dh_config);
    q->out_i32(0);
    q->out_i32(256);
    q->execute(tgl_state::instance()->active_client());
}


/* }}} */
