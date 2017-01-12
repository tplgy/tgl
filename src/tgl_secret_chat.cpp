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

#include "tgl/tgl_secret_chat.h"

#include "crypto/tgl_crypto_bn.h"
#include "crypto/tgl_crypto_sha.h"

#include "mtproto-utils.h"
#include "tgl_secret_chat_private.h"
#include "tgl/tgl.h"
#include "tgl/tgl_log.h"
#include "tools.h"

tgl_secret_chat::tgl_secret_chat()
    : d(std::make_unique<tgl_secret_chat_private>())
{
}

tgl_secret_chat::tgl_secret_chat(int32_t chat_id, int64_t access_hash, int32_t user_id)
    : tgl_secret_chat()
{
    d->m_id = tgl_input_peer_t(tgl_peer_type::enc_chat, chat_id, access_hash);
    d->m_user_id = user_id;
}

tgl_secret_chat::tgl_secret_chat(int32_t chat_id, int64_t access_hash, int32_t user_id,
        int32_t admin, int32_t date, int32_t ttl, int32_t layer,
        int32_t in_seq_no, int32_t last_in_seq, int32_t out_seq_no,
        int32_t encr_root, int32_t encr_param_version,
        tgl_secret_chat_state state, tgl_secret_chat_exchange_state exchange_state,
        int64_t exchange_id,
        const unsigned char* key, size_t key_length,
        const unsigned char* encr_prime, size_t encr_prime_length,
        const unsigned char* g_key, size_t g_key_length,
        const unsigned char* exchange_key, size_t exchange_key_length)
    : tgl_secret_chat(chat_id, access_hash, user_id)
{
    d->m_exchange_id = exchange_id;
    d->m_admin_id = admin;
    d->m_date = date;
    d->m_ttl = ttl;
    d->m_layer = layer;
    d->m_in_seq_no = in_seq_no;
    d->m_last_in_seq_no = last_in_seq;
    d->m_out_seq_no = out_seq_no;
    d->m_encr_root = encr_root;
    d->m_encr_param_version = encr_param_version;
    d->m_state = state;
    d->m_exchange_state = exchange_state;
    assert(key_length == key_size());
    private_facet()->set_key(key);
    private_facet()->set_encr_prime(encr_prime, encr_prime_length);
    private_facet()->set_g_key(g_key, g_key_length);
    private_facet()->set_exchange_key(exchange_key, exchange_key_length);
}

tgl_secret_chat::~tgl_secret_chat()
{
}

const tgl_input_peer_t& tgl_secret_chat::id() const
{
    return d->m_id;
}

int64_t tgl_secret_chat::exchange_id() const
{
    return d->m_exchange_id;
}

int64_t tgl_secret_chat::exchange_key_fingerprint() const
{
    return d->m_exchange_key_fingerprint;
}

int32_t tgl_secret_chat::user_id() const
{
    return d->m_user_id;
}

int32_t tgl_secret_chat::admin_id() const
{
    return d->m_admin_id;
}

int32_t tgl_secret_chat::date() const
{
    return d->m_date;
}

int32_t tgl_secret_chat::ttl() const
{
    return d->m_ttl;
}

int32_t tgl_secret_chat::layer() const
{
    return d->m_layer;
}

int32_t tgl_secret_chat::in_seq_no() const
{
    return d->m_in_seq_no;
}

int32_t tgl_secret_chat::out_seq_no() const
{
    return d->m_out_seq_no;
}

int32_t tgl_secret_chat::last_in_seq_no() const
{
    return d->m_last_in_seq_no;
}

int32_t tgl_secret_chat::encr_root() const
{
    return d->m_encr_root;
}

int32_t tgl_secret_chat::encr_param_version() const
{
    return d->m_encr_param_version;
}

tgl_secret_chat_state tgl_secret_chat::state() const
{
    return d->m_state;
}

tgl_secret_chat_exchange_state tgl_secret_chat::exchange_state() const
{
    return d->m_exchange_state;
}

void tgl_secret_chat_private_facet::set_key(const unsigned char* key)
{
    TGLC_sha1(key, key_size(), d->m_key_sha);
    memcpy(d->m_key, key, key_size());
}

void tgl_secret_chat_private_facet::set_encr_prime(const unsigned char* prime, size_t length)
{
    d->m_encr_prime.resize(length);
    d->m_encr_prime_bn.reset(new tgl_bn(TGLC_bn_new()));
    std::copy(prime, prime + length, d->m_encr_prime.begin());
    TGLC_bn_bin2bn(d->m_encr_prime.data(), length, d->m_encr_prime_bn->bn);
}

bool tgl_secret_chat_private_facet::create_keys_end()
{
    assert(!encr_prime().empty());
    if (encr_prime().empty()) {
        return false;
    }

    std::unique_ptr<TGLC_bn, TGLC_bn_clear_deleter> g_b(TGLC_bn_bin2bn(d->m_g_key.data(), 256, 0));
    if (tglmp_check_g_a(encr_prime_bn()->bn, g_b.get()) < 0) {
        return false;
    }

    TGLC_bn* p = encr_prime_bn()->bn;
    std::unique_ptr<TGLC_bn, TGLC_bn_clear_deleter> r(TGLC_bn_new());
    std::unique_ptr<TGLC_bn, TGLC_bn_clear_deleter> a(TGLC_bn_bin2bn(this->key(), tgl_secret_chat::key_size(), 0));
    check_crypto_result(TGLC_bn_mod_exp(r.get(), g_b.get(), a.get(), p, tgl_state::instance()->bn_ctx()->ctx));

    std::vector<unsigned char> key(tgl_secret_chat::key_size(), 0);

    TGLC_bn_bn2bin(r.get(), (key.data() + (tgl_secret_chat::key_size() - TGLC_bn_num_bytes(r.get()))));
    set_key(key.data());

    if (key_fingerprint() != d->m_temp_key_fingerprint) {
        TGL_WARNING("key fingerprint mismatch (my 0x" << std::hex
                << (uint64_t)key_fingerprint()
                << "x 0x" << (uint64_t)d->m_temp_key_fingerprint << "x)");
        return false;
    }
    d->m_temp_key_fingerprint = 0;
    return true;
}

void tgl_secret_chat_private_facet::set_dh_params(int32_t root, unsigned char prime[], int32_t version)
{
    d->m_encr_root = root;
    set_encr_prime(prime, 256);
    d->m_encr_param_version = version;

    auto res = tglmp_check_DH_params(encr_prime_bn()->bn, encr_root());
    TGL_ASSERT_UNUSED(res, res >= 0);
}

const std::vector<unsigned char>& tgl_secret_chat::encr_prime() const
{
    return d->m_encr_prime;
}

int64_t tgl_secret_chat::key_fingerprint() const
{
    int64_t fingerprint;
    // Telegram secret chat key fingerprints are the last 64 bits of SHA1(key)
    memcpy(&fingerprint, d->m_key_sha + 12, 8);
    return fingerprint;
}

const unsigned char* tgl_secret_chat::key() const
{
    return d->m_key;
}

const unsigned char* tgl_secret_chat::key_sha() const
{
    return d->m_key_sha;
}

const std::vector<unsigned char>& tgl_secret_chat::g_key() const
{
    return d->m_g_key;
}

const unsigned char* tgl_secret_chat::exchange_key() const
{
    return reinterpret_cast<const unsigned char*>(d->m_exchange_key);
}

void tgl_secret_chat_private_facet::set_g_key(const unsigned char* g_key, size_t length)
{
    d->m_g_key.resize(length);
    memcpy(d->m_g_key.data(), g_key, length);
}

void tgl_secret_chat_private_facet::set_exchange_key(const unsigned char* exchange_key, size_t length)
{
    assert(length == sizeof(d->m_exchange_key));
    memcpy(d->m_exchange_key, exchange_key, sizeof(d->m_exchange_key));
}

void tgl_secret_chat_private_facet::set_state(const tgl_secret_chat_state& new_state)
{
    if (d->m_state == tgl_secret_chat_state::waiting && new_state == tgl_secret_chat_state::ok) {
        if (create_keys_end()) {
            d->m_state = new_state;
        } else {
            d->m_state = tgl_secret_chat_state::deleted;
        }
    } else {
        d->m_state = new_state;
    }
}

void tgl_secret_chat_private_facet::queue_pending_received_message(const std::shared_ptr<tgl_message>& message,
        double heal_hole_after_seconds,
        const std::function<void()>& heal_hole)
{
    int32_t out_seq_no = message->secret_message_meta->raw_out_seq_no / 2;
    if (message->secret_message_meta->raw_out_seq_no < 0 || out_seq_no <= in_seq_no()) {
        assert(false);
        return;
    }

    d->m_pending_received_messages.emplace(out_seq_no, message);
    d->m_timer = tgl_state::instance()->timer_factory()->create_timer(heal_hole);
    d->m_timer->start(heal_hole_after_seconds);
}

std::vector<std::shared_ptr<tgl_message>>
tgl_secret_chat_private_facet::dequeue_pending_received_messages(const std::shared_ptr<tgl_message>& new_message)
{
    std::vector<std::shared_ptr<tgl_message>> messages;
    if(new_message->secret_message_meta->raw_in_seq_no < 0 || new_message->secret_message_meta->raw_out_seq_no < 0) {
        assert(false);
        return messages;
    }

    int32_t out_seq_no = new_message->secret_message_meta->raw_out_seq_no / 2;
    d->m_pending_received_messages.emplace(out_seq_no, new_message);
    int32_t in_seq_no = this->in_seq_no();
    auto it = d->m_pending_received_messages.begin();
    while (it != d->m_pending_received_messages.end() && it->first == in_seq_no) {
        in_seq_no++;
        messages.push_back(it->second);
        d->m_pending_received_messages.erase(it);
        it = d->m_pending_received_messages.begin();
    }

    if (messages.size() > 1) {
        TGL_DEBUG("after received a message with out_seq_no " << out_seq_no << " we dequeued " << messages.size() - 1 << " messages, "
                << d->m_pending_received_messages.size() << " out of order messages left");
    }

    return messages;
}

std::vector<std::shared_ptr<tgl_message>>
tgl_secret_chat_private_facet::heal_all_holes()
{
    // FIXME: we should implement request resend the missed message.
    // For now we just skip the holes.

    d->m_timer = nullptr;

    std::vector<std::shared_ptr<tgl_message>> messages;
    int32_t in_seq_no = this->in_seq_no();
    if (!has_hole() || d->m_pending_received_messages.begin()->first <= in_seq_no) {
        assert(false);
        return messages;
    }

    for (const auto& it: d->m_pending_received_messages) {
        messages.push_back(it.second);
    }
    d->m_pending_received_messages.clear();

    TGL_DEBUG("healed all holes");
    return messages;
}
