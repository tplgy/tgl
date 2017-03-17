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
    Copyright Topology LP 2016-2017
*/

#pragma once

#include "crypto/tgl_crypto_bn.h"
#include "crypto/tgl_crypto_sha.h"
#include "tgl/tgl_secret_chat.h"
#include "tgl/tgl_timer.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <utility>
#include <vector>

struct tgl_input_peer_t;
class tgl_unconfirmed_secret_message;

namespace tgl {
namespace impl {

static constexpr int32_t TGL_ENCRYPTED_LAYER = 17;

class message;
class query;
class user_agent;

struct tgl_in_buffer;
struct tl_ds_encrypted_chat;
struct tl_ds_encrypted_message;
struct tl_ds_decrypted_message_action;
struct tl_ds_encrypted_file;

struct secret_message
{
    std::shared_ptr<class message> message;
    int32_t raw_in_seq_no = -1;
    int32_t raw_out_seq_no = -1;
};

class secret_chat: public std::enable_shared_from_this<secret_chat>, public tgl_secret_chat
{
public:
    static std::shared_ptr<secret_chat> create(const std::weak_ptr<user_agent>& weak_ua,
            const tgl_input_peer_t& chat_id, int32_t user_id);

    static std::shared_ptr<secret_chat> create_or_update(const std::weak_ptr<user_agent>& weak_ua,
            const tl_ds_encrypted_chat*);

    static std::shared_ptr<secret_chat> create(const std::weak_ptr<user_agent>& weak_ua,
            int32_t chat_id, int64_t access_hash, int32_t user_id,
            int32_t admin, int32_t date, int32_t ttl, int32_t layer,
            int32_t in_seq_no, int32_t out_seq_no,
            int32_t encr_root, int32_t encr_param_version,
            tgl_secret_chat_state state, tgl_secret_chat_exchange_state exchange_state,
            int64_t exchange_id,
            const unsigned char* key, size_t key_length,
            const unsigned char* encr_prime, size_t encr_prime_length,
            const unsigned char* g_key, size_t g_key_length,
            const unsigned char* exchange_key, size_t exchange_key_length);

    virtual tgl_secret_chat::qos quality_of_service() const override { return m_qos; }
    virtual void set_quality_of_service(qos q) override { m_qos = q; }
    virtual bool opaque_service_message_enabled() const override { return m_opaque_service_message_enabled; }
    virtual void set_opaque_service_message_enabled(bool b) override { m_opaque_service_message_enabled = b; }
    virtual const tgl_input_peer_t& id() const override { return m_id; }
    virtual int64_t exchange_id() const override { return m_exchange_id; }
    virtual int64_t exchange_key_fingerprint() const override { return m_exchange_key_fingerprint; }
    virtual int32_t user_id() const override { return m_user_id; }
    virtual int32_t admin_id() const override { return m_admin_id; }
    virtual int32_t date() const override { return m_date; }
    virtual int32_t ttl() const override { return m_ttl; }
    virtual int32_t layer() const override { return m_layer; }
    virtual int32_t in_seq_no() const override { return m_in_seq_no; }
    virtual int32_t out_seq_no() const override { return m_out_seq_no; }
    virtual int32_t last_in_seq_no() const override { return m_last_in_seq_no; }
    virtual int32_t encr_root() const override { return m_encr_root; }
    virtual int32_t encr_param_version() const override { return m_encr_param_version; }
    virtual tgl_secret_chat_state state() const override { return m_state; }
    virtual tgl_secret_chat_exchange_state exchange_state() const override { return m_exchange_state; }
    virtual const std::vector<unsigned char>& encr_prime() const override { return m_encr_prime; }
    virtual int64_t key_fingerprint() const override
    {
        int64_t fingerprint;
        // Telegram secret chat key fingerprints are the last 64 bits of SHA1(key)
        memcpy(&fingerprint, m_key_sha + 12, 8);
        return fingerprint;
    }
    virtual const unsigned char* key() const override { return m_key; }
    virtual const unsigned char* key_sha() const override { return m_key_sha; }
    virtual const std::vector<unsigned char>& g_key() const override { return m_g_key; }
    virtual const unsigned char* exchange_key() const override { return reinterpret_cast<const unsigned char*>(m_exchange_key); }

    const std::weak_ptr<user_agent>& weak_user_agent() const { return m_user_agent; }
    bool create_keys_end();
    std::pair<int32_t, int32_t> first_hole() const;
    void set_dh_params(int32_t root, unsigned char* prime, int32_t version);
    const std::shared_ptr<query>& last_depending_query() const { return m_last_depending_query; }
    void set_last_depending_query(const std::shared_ptr<query>& q) { m_last_depending_query = q; }
    void set_layer(int32_t layer) { m_layer = layer; }
    void set_ttl(int32_t ttl) { m_ttl = ttl; }
    void set_out_seq_no(int32_t out_seq_no) { m_out_seq_no = out_seq_no; }
    void set_in_seq_no(int32_t in_seq_no) { m_in_seq_no = in_seq_no; }
    const tgl_bn* encr_prime_bn() const { return m_encr_prime_bn.get(); }
    void set_access_hash(int64_t access_hash) { m_id.access_hash = access_hash; }
    void set_date(int64_t date) { m_date = date; }
    void set_admin_id(int32_t admin_id) { m_admin_id = admin_id; }
    void set_user_id(int32_t user_id) { m_user_id = user_id; }
    void set_state(const tgl_secret_chat_state& new_state);
    int64_t temp_key_fingerprint() const { return m_temp_key_fingerprint; }
    void set_temp_key_fingerprint(int64_t fingerprint) { m_temp_key_fingerprint = fingerprint; }
    int32_t raw_in_seq_no() const { return in_seq_no() * 2 + (admin_id() != m_our_id.peer_id); }
    int32_t raw_out_seq_no() const { return out_seq_no() * 2 + (admin_id() == m_our_id.peer_id); }
    int64_t last_depending_query_id() const { return m_last_depending_query_id; }
    void set_last_depending_query_id(int64_t query_id) { m_last_depending_query_id = query_id; }
    const tgl_peer_id_t& our_id() { return m_our_id; }

    void set_key(const unsigned char* key)
    {
        auto key_size = tgl_secret_chat::key_size();
        TGLC_sha1(key, key_size, m_key_sha);
        memcpy(m_key, key, key_size);
    }

    void set_encr_prime(const unsigned char* prime, size_t length)
    {
        m_encr_prime.resize(length);
        m_encr_prime_bn.reset(new tgl_bn(TGLC_bn_new()));
        memcpy(m_encr_prime.data(), prime, length);
        TGLC_bn_bin2bn(m_encr_prime.data(), length, m_encr_prime_bn->bn);
    }

    void set_g_key(const unsigned char* g_key, size_t length)
    {
        m_g_key.resize(length);
        memcpy(m_g_key.data(), g_key, length);
    }

    void set_exchange_key(const unsigned char* exchange_key, size_t length)
    {
        assert(length == sizeof(m_exchange_key));
        memcpy(m_exchange_key, exchange_key, sizeof(m_exchange_key));
    }

    void imbue_encrypted_message(const tl_ds_encrypted_message*);

    void queue_unconfirmed_outgoing_message(const std::shared_ptr<tgl_unconfirmed_secret_message>& unconfirmed_message);

    std::shared_ptr<message> fetch_message(const tl_ds_encrypted_message*);
    std::shared_ptr<message> construct_message(const tgl_peer_id_t& from_id, int64_t message_id,
            int64_t date, const std::string& layer_blob, const std::string& file_info_blob);

    void send_message(const std::shared_ptr<message>& m,
            const std::function<void(bool, const std::shared_ptr<message>&)>& callback);

    void send_action(const tl_ds_decrypted_message_action& action,
            int64_t message_id,
            const std::function<void(bool, const std::shared_ptr<message>&)>& callback);

    void send_location(double latitude, double longitude,
            const std::function<void(bool success, const std::shared_ptr<message>&)>& callback);

    void send_layer();

    void mark_messages_read(int32_t max_time,
            const std::function<void(bool, const std::shared_ptr<message>&)>& callback);

    void delete_message(int64_t message_id,
            const std::function<void(bool, const std::shared_ptr<message>&)>& callback);

    void set_deleted();

    void request_key_exchange();
    void accept_key_exchange(int64_t exchange_id, const std::vector<unsigned char>& ga);
    void confirm_key_exchange(int sen_nop);
    void commit_key_exchange(const std::vector<unsigned char>& gb);
    void abort_key_exchange();

private:
    secret_chat();

    std::pair<secret_message, std::shared_ptr<tgl_unconfirmed_secret_message>>
    fetch_message(const tl_ds_encrypted_message* DS_EM, bool construct_unconfirmed_message);

    std::pair<secret_message, std::shared_ptr<tgl_unconfirmed_secret_message>>
    fetch_message(tgl_in_buffer& in, const tgl_peer_id_t& from_id, int64_t message_id,
            int64_t date, const tl_ds_encrypted_file* file, bool construct_unconfirmed_message);

    void message_received(const secret_message& m, const std::shared_ptr<tgl_unconfirmed_secret_message>& unconfirmed_message);
    bool decrypt_message(int32_t*& decr_ptr, int32_t* decr_end);
    void queue_unconfirmed_incoming_message(const secret_message& m, const std::shared_ptr<tgl_unconfirmed_secret_message>& unconfirmed_message);
    std::vector<secret_message> dequeue_unconfirmed_incoming_messages(const secret_message& new_message);
    void process_messages(const std::vector<secret_message>& messages);
    void load_unconfirmed_incoming_messages_if_needed();
    void load_unconfirmed_outgoing_messages_if_needed();
    void incoming_messages_deleted(const std::vector<int64_t>& message_ids);
    void request_resend_messages(int32_t start_seq_no, int32_t end_seq_no);
    void resend_messages(int32_t start_seq_no, int32_t end_seq_no);

private:
    int64_t m_temp_key_fingerprint;
    int32_t m_exchange_key[64];
    std::vector<unsigned char> m_g_key;
    tgl_input_peer_t m_id;
    tgl_peer_id_t m_our_id;
    int64_t m_exchange_id;
    int64_t m_exchange_key_fingerprint;
    int32_t m_user_id;
    int32_t m_admin_id; // creator
    int32_t m_date;
    int32_t m_ttl;
    int32_t m_layer;
    int32_t m_in_seq_no;
    int32_t m_last_in_seq_no;
    int32_t m_encr_root;
    int32_t m_encr_param_version;
    tgl_secret_chat_state m_state;
    tgl_secret_chat_exchange_state m_exchange_state;

    std::vector<unsigned char> m_encr_prime;
    std::unique_ptr<tgl_bn> m_encr_prime_bn;
    unsigned char m_key[256];
    unsigned char m_key_sha[20];
    int32_t m_out_seq_no;
    std::shared_ptr<query> m_last_depending_query;
    std::map<int32_t, secret_message> m_unconfirmed_incoming_messages;
    std::map<int64_t, int32_t> m_unconfirmed_outgoing_seq_numbers;
    std::map<int32_t, int64_t> m_unconfirmed_outgoing_message_ids;
    std::shared_ptr<tgl_timer> m_fill_hole_timer;
    std::shared_ptr<tgl_timer> m_skip_hole_timer;
    std::weak_ptr<user_agent> m_user_agent;
    int64_t m_last_depending_query_id;
    bool m_unconfirmed_incoming_messages_loaded;
    bool m_unconfirmed_outgoing_messages_loaded;
    bool m_opaque_service_message_enabled;
    tgl_secret_chat::qos m_qos;
};

}
}
