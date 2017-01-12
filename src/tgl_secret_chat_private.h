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
#include <vector>

static constexpr int32_t TGL_ENCRYPTED_LAYER = 17;

class query;

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
    std::map<int32_t, std::shared_ptr<tgl_message>> m_pending_received_messages;
    std::shared_ptr<tgl_timer> m_timer;

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
    void queue_pending_received_message(const std::shared_ptr<tgl_message>& message,
            double heal_hole_after_seconds, const std::function<void()>& heal_hole);
    std::vector<std::shared_ptr<tgl_message>> dequeue_pending_received_messages(const std::shared_ptr<tgl_message>& new_message);
    bool has_hole() const { return !d->m_pending_received_messages.empty(); }
    std::vector<std::shared_ptr<tgl_message>> heal_all_holes();
    int32_t raw_in_seq_no() const { return in_seq_no() * 2 + (admin_id() != tgl_state::instance()->our_id().peer_id); }
    int32_t raw_out_seq_no() const { return out_seq_no() * 2 + (admin_id() == tgl_state::instance()->our_id().peer_id); }
};

inline tgl_secret_chat_private_facet* tgl_secret_chat::private_facet()
{
    return static_cast<tgl_secret_chat_private_facet*>(this);
}

#endif
