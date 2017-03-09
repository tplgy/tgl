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

#include "auto/auto-fetch-ds.h"
#include "auto/auto-free-ds.h"
#include "auto/auto-skip.h"
#include "auto/auto-types.h"
#include "auto/constants.h"
#include "crypto/tgl_crypto_aes.h"
#include "crypto/tgl_crypto_bn.h"
#include "crypto/tgl_crypto_sha.h"
#include "mtproto-common.h"
#include "mtproto-utils.h"
#include "query/query_mark_read_encr.h"
#include "query/query_messages_send_encrypted_action.h"
#include "query/query_messages_send_encrypted_message.h"
#include "tgl_secret_chat_private.h"
#include "tgl/tgl_log.h"
#include "tgl/tgl_unconfirmed_secret_message_storage.h"
#include "tgl/tgl_update_callback.h"
#include "tools.h"
#include "unconfirmed_secret_message.h"
#include "user_agent.h"

constexpr double REQUEST_RESEND_DELAY = 1.0; // seconds
constexpr double HOLE_TTL = 3.0; // seconds

tgl_secret_chat::tgl_secret_chat(std::unique_ptr<tgl_secret_chat_private>&& d)
    : d(std::move(d))
{
}

tgl_secret_chat::~tgl_secret_chat()
{
}

tgl_secret_chat::qos tgl_secret_chat::quality_of_service() const
{
    return d->m_qos;
}

void tgl_secret_chat::set_quality_of_service(qos q)
{
    d->m_qos = q;
}

bool tgl_secret_chat::opaque_service_message_enabled() const
{
    return d->m_opaque_service_message_enabled;
}

void tgl_secret_chat::set_opaque_service_message_enabled(bool b)
{
    d->m_opaque_service_message_enabled = b;
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

    auto ua = d->m_user_agent.lock();
    if (!ua) {
        return false;
    }

    TGLC_bn* p = encr_prime_bn()->bn;
    std::unique_ptr<TGLC_bn, TGLC_bn_clear_deleter> r(TGLC_bn_new());
    std::unique_ptr<TGLC_bn, TGLC_bn_clear_deleter> a(TGLC_bn_bin2bn(this->key(), tgl_secret_chat::key_size(), 0));
    check_crypto_result(TGLC_bn_mod_exp(r.get(), g_b.get(), a.get(), p, ua->bn_ctx()->ctx));

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

void tgl_secret_chat_private_facet::set_dh_params(int32_t root, unsigned char* prime, int32_t version)
{
    auto ua = d->m_user_agent.lock();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        return;
    }

    d->m_encr_root = root;
    set_encr_prime(prime, 256);
    d->m_encr_param_version = version;

    auto res = tglmp_check_DH_params(ua->bn_ctx()->ctx, encr_prime_bn()->bn, encr_root());
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

void tgl_secret_chat_private_facet::message_received(const secret_message& m,
        const std::shared_ptr<tgl_unconfirmed_secret_message>& unconfirmed_message)
{
    const std::shared_ptr<tgl_message>& message = m.message;
    if (!message) {
        return;
    }

    message->set_unread(true);

    int32_t raw_in_seq_no = m.raw_in_seq_no;
    int32_t raw_out_seq_no = m.raw_out_seq_no;

    TGL_DEBUG("secret message received: in_seq_no = " << raw_in_seq_no / 2 << " out_seq_no = " << raw_out_seq_no / 2);

    if (raw_in_seq_no >= 0 && raw_out_seq_no >= 0) {
        if ((raw_out_seq_no & 1) != 1 - (admin_id() == d->m_our_id.peer_id) ||
            (raw_in_seq_no & 1) != (admin_id() == d->m_our_id.peer_id)) {
            TGL_WARNING("bad secret message admin, dropping");
            return;
        }

        if (raw_in_seq_no / 2 > out_seq_no()) {
            TGL_WARNING("in_seq_no " << raw_in_seq_no / 2 << " of remote client is bigger than our out_seq_no of "
                    << out_seq_no() << ", dropping the message");
            return;
        }

        if (raw_out_seq_no / 2 < in_seq_no()) {
            TGL_WARNING("secret message recived with out_seq_no less than the in_seq_no: out_seq_no = "
                    << raw_out_seq_no / 2 << " in_seq_no = " << in_seq_no());
            return;
        }

        if (raw_out_seq_no / 2 > in_seq_no()) {
            TGL_WARNING("hole in seq in secret chat, expecting in_seq_no of "
                    << in_seq_no() << " but " << raw_out_seq_no / 2 << " was received");

            if (message->action && message->action->type() == tgl_message_action_type::resend) {
                // We have to make a special case here for resend message because otherwise we may
                // end up with a deadlock where both sides are requesting resend but the resend will
                // never get processed because of a hole ahead of it.
                auto action = std::static_pointer_cast<tgl_message_action_resend>(message->action);
                TGL_DEBUG("received request for message resend, start-seq: "<< action->start_seq_no << " end-seq: " << action->end_seq_no);
                resend_messages(action->start_seq_no, action->end_seq_no);
                auto secret_message_copy = m;
                secret_message_copy.message = nullptr;
                unconfirmed_message->clear_blobs();
                queue_unconfirmed_incoming_message(secret_message_copy, unconfirmed_message);
            } else {
                queue_unconfirmed_incoming_message(m, unconfirmed_message);
            }
            return;
        }
        process_messages(dequeue_unconfirmed_incoming_messages(m));
    } else if (raw_in_seq_no < 0 && raw_out_seq_no < 0) {
        process_messages({ m });
    } else {
        TGL_WARNING("the secret message sequence number is weird: raw_in_seq_no = " << raw_in_seq_no << " raw_out_seq_no = " << raw_out_seq_no);
    }
}

void tgl_secret_chat_private_facet::load_unconfirmed_incoming_messages_if_needed()
{
    if (d->m_unconfirmed_incoming_messages_loaded) {
        return;
    }

    auto ua = d->m_user_agent.lock();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        return;
    }

    d->m_unconfirmed_incoming_messages_loaded = true;
    auto storage = ua->unconfirmed_secret_message_storage();
    d->m_unconfirmed_incoming_messages.clear();
    auto unconfirmed_messages = storage->load_messages_by_out_seq_no(id().peer_id, in_seq_no() + 1, -1, false);
    tgl_peer_id_t from_id = tgl_peer_id_t(tgl_peer_type::user, user_id());
    for (const auto& unconfirmed_message: unconfirmed_messages) {
        const auto& blobs = unconfirmed_message->blobs();
        secret_message m;
        m.raw_in_seq_no = unconfirmed_message->in_seq_no() * 2 + (admin_id() != d->m_our_id.peer_id);
        m.raw_out_seq_no = unconfirmed_message->out_seq_no() * 2 + (admin_id() == d->m_our_id.peer_id);
        if (!blobs.empty()) {
            if (blobs.size() != 2 && blobs.size() != 1) {
                TGL_WARNING("invalid unconfirmed incoming serecet message, skipping");
                continue;
            }
            m.message = construct_message(from_id, unconfirmed_message->message_id(),
                    unconfirmed_message->date(), blobs[0], blobs.size() == 2 ? blobs[1] : std::string());
            if (!m.message) {
                TGL_WARNING("failed to construct message");
                continue;
            }
        }
        d->m_unconfirmed_incoming_messages.emplace(unconfirmed_message->out_seq_no(), m);
    }
}

void tgl_secret_chat_private_facet::load_unconfirmed_outgoing_messages_if_needed()
{
    if (d->m_unconfirmed_outgoing_messages_loaded) {
        return;
    }

    auto ua = d->m_user_agent.lock();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        return;
    }

    d->m_unconfirmed_outgoing_messages_loaded = true;
    auto storage = ua->unconfirmed_secret_message_storage();
    d->m_unconfirmed_outgoing_seq_numbers.clear();
    d->m_unconfirmed_outgoing_message_ids.clear();
    auto unconfirmed_messages = storage->load_messages_by_out_seq_no(id().peer_id, 0, out_seq_no(), true);
    for (const auto& unconfirmed_message: unconfirmed_messages) {
        if (unconfirmed_message->blobs().empty()) {
            continue;
        }
        d->m_unconfirmed_outgoing_seq_numbers.emplace(unconfirmed_message->message_id(), unconfirmed_message->out_seq_no());
        d->m_unconfirmed_outgoing_message_ids.emplace(unconfirmed_message->out_seq_no(), unconfirmed_message->message_id());
    }
}

void tgl_secret_chat_private_facet::queue_unconfirmed_incoming_message(const secret_message& m,
        const std::shared_ptr<tgl_unconfirmed_secret_message>& unconfirmed_message)
{
    auto ua = d->m_user_agent.lock();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        return;
    }

    assert(m.raw_out_seq_no >= 0);
    int32_t out_seq_no = m.raw_out_seq_no / 2;
    assert(out_seq_no > in_seq_no());

    load_unconfirmed_incoming_messages_if_needed();

    if (unconfirmed_message) {
        ua->unconfirmed_secret_message_storage()->store_message(unconfirmed_message);
    }
    d->m_unconfirmed_incoming_messages.emplace(out_seq_no, m);

    if (!d->m_skip_hole_timer) {
        std::weak_ptr<tgl_secret_chat> weak_secret_chat(shared_from_this());
        d->m_skip_hole_timer = ua->timer_factory()->create_timer([=] {
            auto secret_chat = weak_secret_chat.lock();
            if (!secret_chat) {
                return;
            }
            if (secret_chat->d->m_unconfirmed_incoming_messages.size()) {
                std::vector<secret_message> messages;
                auto it = secret_chat->d->m_unconfirmed_incoming_messages.begin();
                int32_t seq_no = it->first;
                while (it != secret_chat->d->m_unconfirmed_incoming_messages.end() && seq_no == it->first) {
                    messages.push_back(it->second);
                    ++it;
                    seq_no++;
                }
                TGL_DEBUG("skipped hole range [" << secret_chat->in_seq_no() << "," << seq_no - 1 << "] with " << messages.size() << " messages");
                secret_chat->private_facet()->process_messages(messages);
                secret_chat->d->m_unconfirmed_incoming_messages.erase(secret_chat->d->m_unconfirmed_incoming_messages.begin(), it);
            }
            secret_chat->d->m_fill_hole_timer->start(REQUEST_RESEND_DELAY);
        });
    }

    if (!d->m_fill_hole_timer) {
        std::weak_ptr<tgl_secret_chat> weak_secret_chat(shared_from_this());
        d->m_fill_hole_timer = ua->timer_factory()->create_timer([=] {
            auto secret_chat = weak_secret_chat.lock();
            if (!secret_chat) {
                return;
            }
            auto hole = secret_chat->private_facet()->first_hole();
            int32_t hole_start = hole.first;
            int32_t hole_end = hole.second;
            if (hole_start >= 0 && hole_end >= 0) {
                assert(hole_end >= hole_start);
                assert(hole_start == in_seq_no());
                request_resend_messages(hole_start, hole_end);
                if (secret_chat->d->m_qos == tgl_secret_chat::qos::real_time) {
                    secret_chat->d->m_skip_hole_timer->start(HOLE_TTL);
                }
            }
        });
    }

    d->m_fill_hole_timer->start(REQUEST_RESEND_DELAY);
}

std::vector<secret_message>
tgl_secret_chat_private_facet::dequeue_unconfirmed_incoming_messages(const secret_message& m)
{
    assert(m.raw_out_seq_no >= 0);
    assert(m.raw_out_seq_no >= 0);

    std::vector<secret_message> messages;

    int32_t out_seq_no = m.raw_out_seq_no / 2;
    d->m_unconfirmed_incoming_messages.emplace(out_seq_no, m);
    int32_t in_seq_no = this->in_seq_no();
    auto it = d->m_unconfirmed_incoming_messages.begin();
    while (it != d->m_unconfirmed_incoming_messages.end() && it->first == in_seq_no) {
        in_seq_no++;
        messages.push_back(it->second);
        d->m_unconfirmed_incoming_messages.erase(it);
        it = d->m_unconfirmed_incoming_messages.begin();
    }

    if (messages.size() > 1) {
        TGL_DEBUG("after received a message with out_seq_no " << out_seq_no << " we dequeued " << messages.size() - 1 << " messages, "
                << d->m_unconfirmed_incoming_messages.size() << " out of order messages left");
    }

    return messages;
}

void tgl_secret_chat_private_facet::queue_unconfirmed_outgoing_message(
        const std::shared_ptr<tgl_unconfirmed_secret_message>& unconfirmed_message)
{
    if (auto ua = d->m_user_agent.lock()) {
        auto storage = ua->unconfirmed_secret_message_storage();
        storage->store_message(unconfirmed_message);
    }
    d->m_unconfirmed_outgoing_seq_numbers.emplace(unconfirmed_message->message_id(), unconfirmed_message->out_seq_no());
    d->m_unconfirmed_outgoing_message_ids.emplace(unconfirmed_message->out_seq_no(), unconfirmed_message->message_id());
}

std::pair<int32_t, int32_t>
tgl_secret_chat_private_facet::first_hole() const
{
    if (d->m_unconfirmed_incoming_messages.empty()) {
        return std::make_pair(-1, -1);
    }

    int32_t in_seq_no = this->in_seq_no();
    auto it = d->m_unconfirmed_incoming_messages.begin();
    assert(it->first > in_seq_no);
    return std::make_pair(in_seq_no, it->first - 1);
}

void tgl_secret_chat_private_facet::process_messages(const std::vector<secret_message>& messages)
{
    auto ua = d->m_user_agent.lock();
    if (messages.empty() || !ua) {
        return;
    }

    std::vector<std::shared_ptr<tgl_message>> messages_to_deliver;
    for (const auto& m: messages) {
        const auto& message = m.message;
        if (!message) {
            continue;
        }

        if (m.raw_out_seq_no >= 0 && message->from_id.peer_id != d->m_our_id.peer_id) {
            message->seq_no = m.raw_out_seq_no / 2;
        }
        auto action_type = message->action ? message->action->type() : tgl_message_action_type::none;
        if (action_type == tgl_message_action_type::none) {
            messages_to_deliver.push_back(message);
        } else if (action_type == tgl_message_action_type::request_key) {
            auto action = std::static_pointer_cast<tgl_message_action_request_key>(message->action);
            if (exchange_state() == tgl_secret_chat_exchange_state::none
                    || (exchange_state() == tgl_secret_chat_exchange_state::requested && exchange_id() > action->exchange_id )) {
                accept_key_exchange(action->exchange_id, action->g_a);
            } else {
                TGL_WARNING("secret_chat exchange: incorrect state (received request, state = " << exchange_state() << ")");
            }
        } else if (action_type == tgl_message_action_type::accept_key) {
            auto action = std::static_pointer_cast<tgl_message_action_accept_key>(message->action);
            if (exchange_state() == tgl_secret_chat_exchange_state::requested && exchange_id() == action->exchange_id) {
                commit_key_exchange(action->g_a);
            } else {
                TGL_WARNING("secret_chat exchange: incorrect state (received accept, state = " << exchange_state() << ")");
            }
        } else if (action_type == tgl_message_action_type::commit_key) {
            auto action = std::static_pointer_cast<tgl_message_action_commit_key>(message->action);
            if (exchange_state() == tgl_secret_chat_exchange_state::accepted && exchange_id() == action->exchange_id) {
                confirm_key_exchange(1);
            } else {
                TGL_WARNING("secret_chat exchange: incorrect state (received commit, state = " << exchange_state() << ")");
            }
        } else if (action_type == tgl_message_action_type::abort_key) {
            auto action = std::static_pointer_cast<tgl_message_action_abort_key>(message->action);
            if (exchange_state() != tgl_secret_chat_exchange_state::none && exchange_id() == action->exchange_id) {
                abort_key_exchange();
            } else {
                TGL_WARNING("secret_chat exchange: incorrect state (received abort, state = " << exchange_state() << ")");
            }
        } else if (action_type == tgl_message_action_type::notify_layer) {
            auto action = std::static_pointer_cast<tgl_message_action_notify_layer>(message->action);
            set_layer(action->layer);
        } else if (action_type == tgl_message_action_type::set_message_ttl) {
            auto action = std::static_pointer_cast<tgl_message_action_set_message_ttl>(message->action);
            set_ttl(action->ttl);
        } else if (action_type == tgl_message_action_type::delete_messages) {
            auto action = std::static_pointer_cast<tgl_message_action_delete_messages>(message->action);
            incoming_messages_deleted(action->msg_ids);
        } else if (action_type == tgl_message_action_type::resend) {
            auto action = std::static_pointer_cast<tgl_message_action_resend>(message->action);
            TGL_DEBUG("received request for message resend; start-seq: "<< action->start_seq_no << " end-seq: " << action->end_seq_no);
            resend_messages(action->start_seq_no, action->end_seq_no);
        } else if (action_type == tgl_message_action_type::opaque_message) {
            messages_to_deliver.push_back(message);
        }
    }

    int32_t peer_raw_in_seq_no = messages.back().raw_in_seq_no;
    int32_t peer_raw_out_seq_no = messages.back().raw_out_seq_no;

    if (peer_raw_in_seq_no >= 0 && peer_raw_out_seq_no >= 0) {
        set_in_seq_no(peer_raw_out_seq_no / 2 + 1);
        ua->callback()->secret_chat_update(shared_from_this());
    }

    if (messages_to_deliver.size()) {
        ua->callback()->new_or_update_messages(messages_to_deliver);
    }

    if (peer_raw_in_seq_no >= 0 && peer_raw_out_seq_no >= 0) {
        auto storage = ua->unconfirmed_secret_message_storage();
        int32_t peer_in_seq_no = peer_raw_in_seq_no / 2;
        int32_t peer_out_seq_no = peer_raw_out_seq_no / 2;
        if (peer_in_seq_no > 0) {
            auto end = d->m_unconfirmed_outgoing_message_ids.lower_bound(peer_in_seq_no);
            for (auto it = d->m_unconfirmed_outgoing_message_ids.begin(); it != end; ++it) {
                d->m_unconfirmed_outgoing_seq_numbers.erase(it->second);
            }
            d->m_unconfirmed_outgoing_message_ids.erase(d->m_unconfirmed_outgoing_message_ids.begin(), end);
            storage->remove_messages_by_out_seq_no(id().peer_id, 0, peer_in_seq_no - 1, true);
        }
        storage->remove_messages_by_out_seq_no(id().peer_id, 0, peer_out_seq_no, false);
    }
}

bool tgl_secret_chat_private_facet::decrypt_message(int32_t*& decr_ptr, int32_t* decr_end)
{
    int* msg_key = decr_ptr;
    decr_ptr += 4;
    assert(decr_ptr < decr_end);
    unsigned char sha1a_buffer[20];
    unsigned char sha1b_buffer[20];
    unsigned char sha1c_buffer[20];
    unsigned char sha1d_buffer[20];

    unsigned char buf[64];

    memset(sha1a_buffer, 0, sizeof(sha1a_buffer));
    memset(sha1b_buffer, 0, sizeof(sha1b_buffer));
    memset(sha1c_buffer, 0, sizeof(sha1c_buffer));
    memset(sha1d_buffer, 0, sizeof(sha1d_buffer));
    memset(buf, 0, sizeof(buf));

    const int32_t* e_key = exchange_state() != tgl_secret_chat_exchange_state::committed
        ? reinterpret_cast<const int32_t*>(key()) : reinterpret_cast<const int32_t*>(exchange_key());

    memcpy(buf, msg_key, 16);
    memcpy(buf + 16, e_key, 32);
    TGLC_sha1(buf, 48, sha1a_buffer);

    memcpy(buf, e_key + 8, 16);
    memcpy(buf + 16, msg_key, 16);
    memcpy(buf + 32, e_key + 12, 16);
    TGLC_sha1(buf, 48, sha1b_buffer);

    memcpy(buf, e_key + 16, 32);
    memcpy(buf + 32, msg_key, 16);
    TGLC_sha1(buf, 48, sha1c_buffer);

    memcpy(buf, msg_key, 16);
    memcpy(buf + 16, e_key + 24, 32);
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
    TGLC_aes_set_decrypt_key(key, 256, &aes_key);
    TGLC_aes_ige_encrypt(reinterpret_cast<const unsigned char*>(decr_ptr),
            reinterpret_cast<unsigned char*>(decr_ptr), 4 * (decr_end - decr_ptr), &aes_key, iv, 0);
    memset(&aes_key, 0, sizeof(aes_key));

    int32_t x = *decr_ptr;
    if (x < 0 || (x & 3)) {
        return false;
    }
    assert(x >= 0 && !(x & 3));
    TGLC_sha1(reinterpret_cast<const unsigned char*>(decr_ptr), 4 + x, sha1a_buffer);

    if (memcmp(sha1a_buffer + 4, msg_key, 16)) {
        return false;
    }

    return true;
}

std::shared_ptr<tgl_message> tgl_secret_chat_private_facet::fetch_message(const tl_ds_encrypted_message* DS_EM)
{
    return fetch_message(DS_EM, false).first.message;
}

std::pair<secret_message, std::shared_ptr<tgl_unconfirmed_secret_message>>
tgl_secret_chat_private_facet::fetch_message(const tl_ds_encrypted_message* DS_EM, bool construct_unconfirmed_message)
{
    std::pair<secret_message, std::shared_ptr<tgl_unconfirmed_secret_message>> message_pair;

    int64_t message_id = DS_LVAL(DS_EM->random_id);
    int32_t* decr_ptr = reinterpret_cast<int32_t*>(DS_EM->bytes->data);
    int32_t* decr_end = decr_ptr + (DS_EM->bytes->len / 4);

    if (exchange_state() == tgl_secret_chat_exchange_state::committed && key_fingerprint() == *(int64_t*)decr_ptr) {
        confirm_key_exchange(0);
        assert(exchange_state() == tgl_secret_chat_exchange_state::none);
    }

    int64_t key_fingerprint = exchange_state() != tgl_secret_chat_exchange_state::committed ? this->key_fingerprint() : exchange_key_fingerprint();
    if (*(int64_t*)decr_ptr != key_fingerprint) {
        TGL_WARNING("encrypted message with bad fingerprint to chat " << id().peer_id);
        return message_pair;
    }

    decr_ptr += 2;

    if (!decrypt_message(decr_ptr, decr_end)) {
        TGL_WARNING("can not decrypt message");
        return message_pair;
    }

    int32_t decrypted_data_length = *decr_ptr;
    tgl_in_buffer in = { decr_ptr, decr_ptr + decrypted_data_length / 4 + 1 };
    auto ret = fetch_i32(&in);
    TGL_ASSERT_UNUSED(ret, ret == decrypted_data_length);

    tgl_peer_id_t from_id = tgl_peer_id_t(tgl_peer_type::user, user_id());
    return fetch_message(in, from_id, message_id, DS_LVAL(DS_EM->date), DS_EM->file, construct_unconfirmed_message);
}

std::pair<secret_message, std::shared_ptr<tgl_unconfirmed_secret_message>>
tgl_secret_chat_private_facet::fetch_message(tgl_in_buffer& in, const tgl_peer_id_t& from_id, int64_t message_id,
        int64_t date, const tl_ds_encrypted_file* file, bool construct_unconfirmed_message)
{
    secret_message m;
    std::shared_ptr<tgl_unconfirmed_secret_message> unconfirmed_message;

    if (*in.ptr == CODE_decrypted_message_layer) {
        struct paramed_type decrypted_message_layer = TYPE_TO_PARAM(decrypted_message_layer);
        tgl_in_buffer skip_in = in;
        if (skip_type_decrypted_message_layer(&skip_in, &decrypted_message_layer) < 0 || skip_in.ptr != skip_in.end) {
            TGL_WARNING("can not fetch message");
            return std::make_pair(m, nullptr);;
        }

        std::string layer_blob;
        if (construct_unconfirmed_message) {
            layer_blob = std::string(reinterpret_cast<const char*>(in.ptr), (in.end - in.ptr) * 4);
        }

        struct tl_ds_decrypted_message_layer* DS_DML = fetch_ds_type_decrypted_message_layer(&in, &decrypted_message_layer);
        assert(DS_DML);

        struct tl_ds_decrypted_message* DS_DM = DS_DML->message;
        if (message_id != DS_LVAL(DS_DM->random_id)) {
            TGL_ERROR("incorrect message: id = " << message_id << ", new_id = " << DS_LVAL(DS_DM->random_id));
            free_ds_type_decrypted_message_layer(DS_DML, &decrypted_message_layer);
            return std::make_pair(m, nullptr);;
        }

        m.message = std::make_shared<tgl_message>(shared_from_this(),
                message_id,
                from_id,
                &date,
                DS_STDSTR(DS_DM->message),
                DS_DM->media,
                DS_DM->action,
                file);
        m.raw_in_seq_no = DS_LVAL(DS_DML->in_seq_no);
        m.raw_out_seq_no = DS_LVAL(DS_DML->out_seq_no);
        if (m.message->is_outgoing()) {
            m.message->seq_no = m.raw_out_seq_no / 2;
        } else {
            m.message->seq_no = m.raw_in_seq_no / 2;
        }

        if (construct_unconfirmed_message) {
            unconfirmed_message = unconfirmed_secret_message::create_default_impl(
                    message_id,
                    date,
                    id().peer_id,
                    m.raw_in_seq_no / 2,
                    m.raw_out_seq_no / 2,
                    false,
                    0/* we don't use constructor code for incoming messages*/);
            unconfirmed_message->append_blob(std::move(layer_blob));
        }

        free_ds_type_decrypted_message_layer(DS_DML, &decrypted_message_layer);
    } else {
        struct paramed_type decrypted_message = TYPE_TO_PARAM(decrypted_message);
        tgl_in_buffer skip_in = in;
        if (skip_type_decrypted_message(&skip_in, &decrypted_message) < 0 || skip_in.ptr != skip_in.end) {
            TGL_WARNING("can not fetch message");
            return std::make_pair(m, nullptr);;
        }

        struct tl_ds_decrypted_message* DS_DM = fetch_ds_type_decrypted_message(&in, &decrypted_message);
        assert(DS_DM);

        m.message = std::make_shared<tgl_message>(shared_from_this(),
                message_id,
                from_id,
                &date,
                DS_STDSTR(DS_DM->message),
                DS_DM->media,
                DS_DM->action,
                file);
        m.raw_in_seq_no = -1;
        m.raw_out_seq_no = -1;
    }

    if (construct_unconfirmed_message && unconfirmed_message && file && m.message->media
            && m.message->media->type() == tgl_message_media_type::document_encr) {
        mtprotocol_serializer s;
        s.out_i32(CODE_encrypted_file);
        s.out_i64(DS_LVAL(file->id));
        s.out_i64(DS_LVAL(file->access_hash));
        s.out_i32(DS_LVAL(file->size));
        s.out_i32(DS_LVAL(file->dc_id));
        s.out_i32(DS_LVAL(file->key_fingerprint));
        unconfirmed_message->append_blob(std::string(s.char_data(), s.char_size()));
    }

    return std::make_pair(m, unconfirmed_message);
}

std::shared_ptr<tgl_message> tgl_secret_chat_private_facet::construct_message(const tgl_peer_id_t& from_id,
        int64_t message_id, int64_t date, const std::string& layer_blob, const std::string& file_info_blob)
{
    if ((layer_blob.size() % 4) || (file_info_blob.size() % 4)) {
        TGL_ERROR("invalid blob sizes for incoming secret message");
        return nullptr;
    }

    paramed_type encrypted_file_type = TYPE_TO_PARAM(encrypted_file);
    tl_ds_encrypted_file* file = nullptr;
    if (file_info_blob.size()) {
        tgl_in_buffer in = { reinterpret_cast<const int*>(file_info_blob.data()), reinterpret_cast<const int*>(file_info_blob.data()) + file_info_blob.size() / 4 };
        file = fetch_ds_type_encrypted_file(&in, &encrypted_file_type);
        if (!file || in.ptr != in.end) {
            if (file) {
                free_ds_type_encrypted_file(file, &encrypted_file_type);
            }
            TGL_ERROR("invalid file blob for incoming secret message");
            assert(false);
            return nullptr;
        }
    }

    tgl_in_buffer in = { reinterpret_cast<const int*>(layer_blob.data()), reinterpret_cast<const int*>(layer_blob.data()) + layer_blob.size() / 4 };
    auto message_pair = fetch_message(in, from_id, message_id, date, file, false);
    if (file) {
        free_ds_type_encrypted_file(file, &encrypted_file_type);
    }

    return message_pair.first.message;
}

void tgl_secret_chat_private_facet::imbue_encrypted_message(const tl_ds_encrypted_message* DS_EM)
{
    if (!DS_EM) {
        return;
    }

    auto message_pair = fetch_message(DS_EM, true);
    message_received(message_pair.first, message_pair.second);
}

void tgl_secret_chat_private_facet::incoming_messages_deleted(const std::vector<int64_t>& message_ids)
{
    auto ua = d->m_user_agent.lock();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        return;
    }

    load_unconfirmed_incoming_messages_if_needed();

    const auto& storage = ua->unconfirmed_secret_message_storage();
    for (int64_t id : message_ids) {
        bool is_unconfirmed = false;
        for (auto& it: d->m_unconfirmed_incoming_messages) {
            const auto& message = it.second.message;
            if (message && message->permanent_id == id) {
               auto unconfirmed_message = unconfirmed_secret_message::create_default_impl(
                        id,
                        message->date,
                        this->id().peer_id,
                        it.second.raw_in_seq_no / 2,
                        it.second.raw_out_seq_no / 2,
                        false,
                        0);
                storage->update_message(unconfirmed_message);
                it.second.message = nullptr;
                is_unconfirmed = true;
                break;
            }
        }
        if (!is_unconfirmed) {
            ua->callback()->message_deleted(id, this->id());
        }
    }
}

void tgl_secret_chat_private_facet::send_message(const std::shared_ptr<tgl_message>& message,
        const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback)
{
    auto ua = d->m_user_agent.lock();
    if (state() != tgl_secret_chat_state::ok || !ua) {
        if (!ua) {
            TGL_ERROR("the user agent has gone");
        } else {
            TGL_ERROR("secret chat " << id().peer_id << " is not in ok state");
        }
        if (callback) {
            callback(false, nullptr);
        }
        return;
    }

    assert(message->permanent_id);

    std::shared_ptr<query> q;

    load_unconfirmed_outgoing_messages_if_needed();
    const auto& it = d->m_unconfirmed_outgoing_seq_numbers.find(message->permanent_id);
    if (it != d->m_unconfirmed_outgoing_seq_numbers.end()) {
        auto queries = query_messages_send_encrypted_base::create_by_out_seq_no(shared_from_this(), it->second, it->second);
        if (queries.size() == 1) {
            q = *(queries.begin());
        }
    }

    if (!q) {
        if (message->is_service()) {
            if (!message->action) {
                if (callback) {
                    TGL_WARNING("we can't send a service message which doesn't have an action");
                    callback(true, nullptr);
                }
                return;
            }
            q = std::make_shared<query_messages_send_encrypted_action>(shared_from_this(), message, callback);
        } else {
            q = std::make_shared<query_messages_send_encrypted_message>(shared_from_this(), message, callback);
        }
    }

    ua->callback()->new_or_update_messages({message});
    q->execute(ua->active_client());
}

void tgl_secret_chat_private_facet::send_action(const tl_ds_decrypted_message_action& action,
        int64_t message_id,
        const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback)
{
    if (action.magic == CODE_decrypted_message_action_opaque_message && !opaque_service_message_enabled()) {
        TGL_ERROR("opaque service message disabled");
        if (callback) {
            callback(false, nullptr);
        }
        return;
    }

    int64_t date = tgl_get_system_time();

    while (!message_id) {
        tgl_secure_random(reinterpret_cast<unsigned char*>(&message_id), 8);
    }

    auto message = std::make_shared<tgl_message>(shared_from_this(),
            message_id,
            d->m_our_id,
            &date,
            std::string(),
            nullptr,
            &action,
            nullptr);
    message->set_pending(true).set_unread(true);
    send_message(message, callback);
}

void tgl_secret_chat_private_facet::send_location(double latitude, double longitude,
        const std::function<void(bool success, const std::shared_ptr<tgl_message>&)>& callback)
{
    struct tl_ds_decrypted_message_media TDSM;
    memset(&TDSM, 0, sizeof(TDSM));
    TDSM.magic = CODE_decrypted_message_media_geo_point;
    TDSM.latitude = &latitude;
    TDSM.longitude = &longitude;

    int64_t date = tgl_get_system_time();

    int64_t message_id = 0;
    while (!message_id) {
        tgl_secure_random(reinterpret_cast<unsigned char*>(&message_id), 8);
    }
    auto message = std::make_shared<tgl_message>(shared_from_this(),
            message_id,
            d->m_our_id,
            &date,
            std::string(),
            &TDSM,
            nullptr,
            nullptr);
    message->set_unread(true).set_pending(true);
    send_message(message, callback);
}

void tgl_secret_chat_private_facet::send_layer()
{
    struct tl_ds_decrypted_message_action action;
    memset(&action, 0, sizeof(action));
    action.magic = CODE_decrypted_message_action_notify_layer;
    int layer = TGL_ENCRYPTED_LAYER;
    action.layer = &layer;

    std::weak_ptr<user_agent> weak_ua = d->m_user_agent;
    send_action(action, 0, [=](bool success, const std::shared_ptr<tgl_message>& msg) {
        if (success) {
            if (auto ua = weak_ua.lock()) {
                ua->callback()->secret_chat_update(shared_from_this());
            }
        }
    });
}

void tgl_secret_chat_private_facet::mark_messages_read(int32_t max_time,
        const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback)
{
    auto ua = d->m_user_agent.lock();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        if (callback) {
            callback(false, nullptr);
        }
        return;
    }

    auto q = std::make_shared<query_mark_read_encr>(shared_from_this(), max_time, callback);
    q->out_i32(CODE_messages_read_encrypted_history);
    q->out_i32(CODE_input_encrypted_chat);
    q->out_i32(id().peer_id);
    q->out_i64(id().access_hash);
    q->out_i32(max_time); // FIXME
    q->execute(ua->active_client());
}

void tgl_secret_chat_private_facet::set_deleted()
{
    set_state(tgl_secret_chat_state::deleted);
    if (auto ua = d->m_user_agent.lock()) {
        ua->callback()->secret_chat_update(shared_from_this());
    }
}

void tgl_secret_chat_private_facet::delete_message(int64_t message_id,
        const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback)
{
    struct tl_ds_decrypted_message_action action;
    action.magic = CODE_decrypted_message_action_delete_messages;

    std::remove_pointer<decltype(action.random_ids)>::type ids;

    int count = 1;
    ids.cnt = &count;
    int64_t *msg_id_ptr = &message_id;
    ids.data = &msg_id_ptr;

    action.random_ids = &ids;
    send_action(action, 0, callback);
}

void tgl_secret_chat_private_facet::request_resend_messages(int32_t start_seq_no, int32_t end_seq_no)
{
    TGL_DEBUG("requesting to resend range [" << start_seq_no << "," << end_seq_no << "]");

    tl_ds_decrypted_message_action action;
    action.magic = CODE_decrypted_message_action_resend;
    action.start_seq_no = &start_seq_no;
    action.end_seq_no = &end_seq_no;

    send_action(action, 0, nullptr);
}

void tgl_secret_chat_private_facet::resend_messages(int32_t start_seq_no, int32_t end_seq_no)
{
    if (start_seq_no < 0 || end_seq_no < 0 || end_seq_no < start_seq_no) {
        return;
    }

    auto ua = d->m_user_agent.lock();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        return;
    }

    TGL_DEBUG("trying to resend range [" << start_seq_no << "," << end_seq_no << "]");

    auto queries = query_messages_send_encrypted_base::create_by_out_seq_no(shared_from_this(), start_seq_no, end_seq_no);

    for (const auto& q: queries) {
        q->execute(ua->active_client());
    }
}

void tgl_secret_chat_private_facet::request_key_exchange()
{
    assert(false);
    exit(2);
}

void tgl_secret_chat_private_facet::accept_key_exchange(
        int64_t exchange_id, const std::vector<unsigned char>& ga)
{
    assert(false);
    exit(2);
}

void tgl_secret_chat_private_facet::confirm_key_exchange(int sen_nop)
{
    assert(false);
    exit(2);
}

void tgl_secret_chat_private_facet::commit_key_exchange(const std::vector<unsigned char>& gb)
{
    assert(false);
    exit(2);
}

void tgl_secret_chat_private_facet::abort_key_exchange()
{
    assert(false);
    exit(2);
}
