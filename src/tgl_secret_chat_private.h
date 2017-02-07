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

#ifndef __TGL_SECRET_CHAT_PRIVATE_H__
#define __TGL_SECRET_CHAT_PRIVATE_H__

#include "tgl/tgl.h"

#include "crypto/tgl_crypto_bn.h"
#include "tgl/tgl_message.h"
#include "tgl/tgl_secret_chat.h"
#include "tgl/tgl_timer.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <functional>
#include <map>
#include <utility>
#include <vector>

static constexpr int32_t TGL_ENCRYPTED_LAYER = 17;

class query;
class tgl_unconfirmed_secret_message;

struct secret_message {
    std::shared_ptr<tgl_message> message;
    int32_t raw_in_seq_no = -1;
    int32_t raw_out_seq_no = -1;
};

struct tgl_secret_chat_private {
    int64_t m_temp_key_fingerprint;
    int32_t m_exchange_key[64];
    std::vector<unsigned char> m_g_key;
    tgl_input_peer_t m_id;
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
    std::map<int32_t, secret_message> m_pending_received_messages;
    std::shared_ptr<tgl_timer> m_fill_hole_timer;
    std::shared_ptr<tgl_timer> m_skip_hole_timer;
    int64_t m_last_depending_query_id;
    bool m_unconfirmed_message_loaded;
    tgl_secret_chat::qos m_qos;

    tgl_secret_chat_private()
        : m_temp_key_fingerprint(0)
        , m_g_key()
        , m_id()
        , m_exchange_id(0)
        , m_exchange_key_fingerprint(0)
        , m_user_id(0)
        , m_admin_id(0)
        , m_date(0)
        , m_ttl(0)
        , m_layer(0)
        , m_in_seq_no(0)
        , m_last_in_seq_no(0)
        , m_encr_root(0)
        , m_encr_param_version(0)
        , m_state(tgl_secret_chat_state::none)
        , m_exchange_state(tgl_secret_chat_exchange_state::none)
        , m_encr_prime()
        , m_encr_prime_bn(nullptr)
        , m_out_seq_no(0)
        , m_last_depending_query_id(0)
        , m_unconfirmed_message_loaded(false)
        , m_qos(tgl_secret_chat::qos::normal)
    {
        memset(m_key, 0, sizeof(m_key));
        memset(m_key_sha, 0, sizeof(m_key_sha));
        memset(m_exchange_key, 0, sizeof(m_exchange_key));
    }
};

// This is a private facet. Don't add any thing (like data member, virtual functions etc)
// that changes the memory layout.
class tgl_secret_chat_private_facet: public tgl_secret_chat {
public:
    bool create_keys_end();
    void set_dh_params(int32_t root, unsigned char prime[], int32_t version);
    const std::shared_ptr<query>& last_depending_query() const { return d->m_last_depending_query; }
    void set_last_depending_query(const std::shared_ptr<query>& q) { d->m_last_depending_query = q; }
    void set_layer(int32_t layer) { d->m_layer = layer; }
    void set_ttl(int32_t ttl) { d->m_ttl = ttl; }
    void set_out_seq_no(int32_t out_seq_no) { d->m_out_seq_no = out_seq_no; }
    void set_in_seq_no(int32_t in_seq_no) { d->m_in_seq_no = in_seq_no; }
    const tgl_bn* encr_prime_bn() const { return d->m_encr_prime_bn.get(); }
    void set_encr_prime(const unsigned char* prime, size_t length);
    void set_key(const unsigned char* key);
    void set_g_key(const unsigned char* g_key, size_t length);
    void set_exchange_key(const unsigned char* exchange_key, size_t length);
    void set_access_hash(int64_t access_hash) { d->m_id.access_hash = access_hash; }
    void set_date(int64_t date) { d->m_date = date; }
    void set_admin_id(int32_t admin_id) { d->m_admin_id = admin_id; }
    void set_user_id(int32_t user_id) { d->m_user_id = user_id; }
    void set_state(const tgl_secret_chat_state& new_state);
    int64_t temp_key_fingerprint() const { return d->m_temp_key_fingerprint; }
    void set_temp_key_fingerprint(int64_t fingerprint) { d->m_temp_key_fingerprint = fingerprint; }
    std::pair<int32_t, int32_t> first_hole() const;
    int32_t raw_in_seq_no() const { return in_seq_no() * 2 + (admin_id() != tgl_state::instance()->our_id().peer_id); }
    int32_t raw_out_seq_no() const { return out_seq_no() * 2 + (admin_id() == tgl_state::instance()->our_id().peer_id); }
    int64_t last_depending_query_id() const { return d->m_last_depending_query_id; }
    void set_last_depending_query_id(int64_t query_id) { d->m_last_depending_query_id = query_id; }

    std::shared_ptr<tgl_message> fetch_message(const tl_ds_encrypted_message*);
    std::shared_ptr<tgl_message> construct_message(int64_t message_id, int64_t date,
            const std::string& layer_blob, const std::string& file_info_blob);

    void send_message(const std::shared_ptr<tgl_message>& message,
            const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback);

    void send_action(const tl_ds_decrypted_message_action& action,
            const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback);

    void send_location(double latitude, double longitude,
            const std::function<void(bool success, const std::shared_ptr<tgl_message>&)>& callback);

    void send_layer();

    void mark_messages_read(int32_t max_time,
            const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback);

    void delete_message(int64_t message_id,
            const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback);

    void set_deleted();

    static void imbue_encrypted_message(const tl_ds_encrypted_message*);

    void request_key_exchange();
    void accept_key_exchange(int64_t exchange_id, const std::vector<unsigned char>& ga);
    void confirm_key_exchange(int sen_nop);
    void commit_key_exchange(const std::vector<unsigned char>& gb);
    void abort_key_exchange();

private:
    std::pair<secret_message, std::shared_ptr<tgl_unconfirmed_secret_message>>
    fetch_message(const tl_ds_encrypted_message* DS_EM, bool construct_unconfirmed_message);

    std::pair<secret_message, std::shared_ptr<tgl_unconfirmed_secret_message>>
    fetch_message(tgl_in_buffer& in, int64_t message_id,
            int64_t date, const tl_ds_encrypted_file* file, bool construct_unconfirmed_message);

    void message_received(const secret_message& m, const std::shared_ptr<tgl_unconfirmed_secret_message>& unconfirmed_message);
    bool decrypt_message(int32_t*& decr_ptr, int32_t* decr_end);
    void queue_pending_received_message(const secret_message& m, const std::shared_ptr<tgl_unconfirmed_secret_message>& unconfirmed_message);
    std::vector<secret_message> dequeue_pending_received_messages(const secret_message& new_message);
    void process_messages(const std::vector<secret_message>& messages);
    void load_unconfirmed_messages_if_needed();
    void messages_deleted(const std::vector<int64_t>& message_ids);
    void request_resend_messages(int32_t start_seq_no, int32_t end_seq_no);
    void resend_messages(int32_t start_seq_no, int32_t end_seq_no);
};

inline tgl_secret_chat_private_facet* tgl_secret_chat::private_facet()
{
    return static_cast<tgl_secret_chat_private_facet*>(this);
}

#endif
