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

#include "secret_chat.h"

#include "auto/auto_fetch_ds.h"
#include "auto/auto_free_ds.h"
#include "auto/auto_skip.h"
#include "auto/auto_types.h"
#include "auto/constants.h"
#include "crypto/crypto_aes.h"
#include "crypto/crypto_bn.h"
#include "crypto/crypto_sha.h"
#include "message.h"
#include "mtproto_common.h"
#include "mtproto_utils.h"
#include "query/query_mark_read_encr.h"
#include "query/query_messages_send_encrypted_action.h"
#include "query/query_messages_send_encrypted_message.h"
#include "tgl/tgl_log.h"
#include "tgl/tgl_unconfirmed_secret_message_storage.h"
#include "tgl/tgl_update_callback.h"
#include "tools.h"
#include "unconfirmed_secret_message.h"
#include "user_agent.h"

#include <cstring>

namespace tgl {
namespace impl {

constexpr double REQUEST_RESEND_DELAY = 1.0; // seconds
constexpr double HOLE_TTL = 3.0; // seconds

inline static void str_to_256(unsigned char* dst, const char* src, int src_len)
{
    if (src_len >= 256) {
        memcpy(dst, src + src_len - 256, 256);
    } else {
        memset(dst, 0, 256 - src_len);
        memcpy(dst + 256 - src_len, src, src_len);
    }
}

std::shared_ptr<secret_chat> secret_chat::create(const std::weak_ptr<user_agent>& weak_ua,
        const tgl_input_peer_t& chat_id, int32_t user_id)
{
    auto ua = weak_ua.lock();
    if (!ua) {
        return nullptr;
    }

    std::shared_ptr<secret_chat> sc(new secret_chat());
    sc->m_user_agent = weak_ua;
    sc->m_id = chat_id;
    sc->m_user_id = user_id;
    sc->m_our_id = ua->our_id();

    return sc;
}

std::shared_ptr<secret_chat> secret_chat::create_or_update(const std::weak_ptr<user_agent>& weak_ua,
        const tl_ds_encrypted_chat* DS_EC)
{
    auto ua = weak_ua.lock();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        return nullptr;
    }

    if (!DS_EC) {
        TGL_ERROR("null raw secret chat");
        return nullptr;
    }

    if (DS_EC->magic == CODE_encrypted_chat_empty) {
        TGL_DEBUG("empty secret chat found, discarding");
        return nullptr;
    }

    tgl_input_peer_t chat_id(tgl_peer_type::enc_chat, DS_LVAL(DS_EC->id), DS_LVAL(DS_EC->access_hash));

    std::shared_ptr<secret_chat> sc = ua->secret_chat_for_id(chat_id);

    bool is_new = false;
    if (!sc) {
        int admin_id = DS_LVAL(DS_EC->id);

        if (!admin_id) {
            // It must be a secret chat which is encryptedChatDiscarded#13d6dd27.
            // For a discarded secret chat which is not on our side either, we do nothing.
            TGL_DEBUG("discarded secret chat " << chat_id.peer_id << " found, doing nothing");
            return nullptr;
        }

        if (admin_id != ua->our_id().peer_id) {
            // It must be a new secret chat requested from the peer.
            sc = ua->allocate_secret_chat(chat_id, DS_LVAL(DS_EC->participant_id));
            is_new = true;
            TGL_DEBUG("new secret chat " << chat_id.peer_id << " found");
        }
    }

    if (!sc) {
        TGL_DEBUG("no secret chat found or created for id " << chat_id.peer_id);
        return nullptr;
    }

    if (DS_EC->magic == CODE_encrypted_chat_discarded) {
        if (is_new) {
            TGL_DEBUG("this is a new scret chat " << chat_id.peer_id << " but has been discarded, doing nothing");
            return nullptr;
        }

        TGL_DEBUG("discarded secret chat " << chat_id.peer_id << " found, setting it to deleted state");
        sc->set_deleted();
        return sc;
    }

    unsigned char g_key[256];
    memset(g_key, 0, sizeof(g_key));
    if (is_new) {
        if (DS_EC->magic != CODE_encrypted_chat_requested) {
            TGL_DEBUG("new secret chat " << chat_id.peer_id << " but not in requested state");
            return sc;
        }
        TGL_DEBUG("updating new secret chat " << chat_id.peer_id);

        str_to_256(g_key, DS_STR(DS_EC->g_a));

        int32_t user_id = DS_LVAL(DS_EC->participant_id) + DS_LVAL(DS_EC->admin_id) - ua->our_id().peer_id;
        if (DS_EC->access_hash) {
            sc->set_access_hash(*(DS_EC->access_hash));
        }
        if (DS_EC->date) {
            sc->set_date(*(DS_EC->date));
        }
        if (DS_EC->admin_id) {
            sc->set_admin_id(*(DS_EC->admin_id));
        }
        sc->set_user_id(user_id);
        sc->set_g_key(g_key, sizeof(g_key));
        sc->set_state(tgl_secret_chat_state::request);
    } else {
        TGL_DEBUG("updating existing secret chat " << chat_id.peer_id);
        tgl_secret_chat_state state;
        if (DS_EC->magic == CODE_encrypted_chat_waiting) {
            state = tgl_secret_chat_state::waiting;
        } else {
            state = tgl_secret_chat_state::ok;
            str_to_256(g_key, DS_STR(DS_EC->g_a_or_b));
            sc->set_temp_key_fingerprint(DS_LVAL(DS_EC->key_fingerprint));
            sc->set_g_key(g_key, sizeof(g_key));
        }
        if (DS_EC->access_hash) {
            sc->set_access_hash(*(DS_EC->access_hash));
        }
        if (DS_EC->date) {
            sc->set_date(*(DS_EC->date));
        }
        sc->set_state(state);
    }

    return sc;
}

std::shared_ptr<secret_chat> secret_chat::create(const std::weak_ptr<user_agent>& weak_ua,
        int32_t chat_id, int64_t access_hash, int32_t user_id,
        int32_t admin, int32_t date, int32_t ttl, int32_t layer,
        int32_t in_seq_no, int32_t out_seq_no,
        int32_t encr_root, int32_t encr_param_version,
        tgl_secret_chat_state state, tgl_secret_chat_exchange_state exchange_state,
        int64_t exchange_id,
        const unsigned char* key, size_t key_length,
        const unsigned char* encr_prime, size_t encr_prime_length,
        const unsigned char* g_key, size_t g_key_length,
        const unsigned char* exchange_key, size_t exchange_key_length)
{
    auto ua = weak_ua.lock();
    if (!ua) {
        return nullptr;
    }

    std::shared_ptr<secret_chat> sc(new secret_chat());
    sc->m_user_agent = weak_ua;
    sc->m_id = tgl_input_peer_t(tgl_peer_type::enc_chat, chat_id, access_hash);
    sc->m_user_id = user_id;
    sc->m_our_id = ua->our_id();
    sc->m_exchange_id = exchange_id;
    sc->m_admin_id = admin;
    sc->m_date = date;
    sc->m_ttl = ttl;
    sc->m_layer = layer;
    sc->m_in_seq_no = in_seq_no;
    sc->m_out_seq_no = out_seq_no;
    sc->m_encr_root = encr_root;
    sc->m_encr_param_version = encr_param_version;
    sc->m_state = state;
    sc->m_exchange_state = exchange_state;
    assert(key_length == secret_chat::key_size());
    sc->set_key(key);
    sc->set_encr_prime(encr_prime, encr_prime_length);
    sc->set_g_key(g_key, g_key_length);
    sc->set_exchange_key(exchange_key, exchange_key_length);

    return sc;
}

secret_chat::secret_chat()
    : m_temp_key_fingerprint(0)
    , m_g_key()
    , m_id()
    , m_our_id()
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
    , m_unconfirmed_incoming_messages_loaded(false)
    , m_unconfirmed_outgoing_messages_loaded(false)
    , m_opaque_service_message_enabled(false)
    , m_qos(secret_chat::qos::normal)
{
    memset(m_key, 0, sizeof(m_key));
    memset(m_key_sha, 0, sizeof(m_key_sha));
    memset(m_exchange_key, 0, sizeof(m_exchange_key));
}


bool secret_chat::create_keys_end()
{
    assert(!encr_prime().empty());
    if (encr_prime().empty()) {
        return false;
    }

    std::unique_ptr<TGLC_bn, TGLC_bn_clear_deleter> g_b(TGLC_bn_bin2bn(m_g_key.data(), 256, 0));
    if (tglmp_check_g_a(encr_prime_bn()->bn, g_b.get()) < 0) {
        return false;
    }

    auto ua = m_user_agent.lock();
    if (!ua) {
        return false;
    }

    TGLC_bn* p = encr_prime_bn()->bn;
    std::unique_ptr<TGLC_bn, TGLC_bn_clear_deleter> r(TGLC_bn_new());
    std::unique_ptr<TGLC_bn, TGLC_bn_clear_deleter> a(TGLC_bn_bin2bn(this->key(), secret_chat::key_size(), 0));
    check_crypto_result(TGLC_bn_mod_exp(r.get(), g_b.get(), a.get(), p, ua->bn_ctx()->ctx));

    std::vector<unsigned char> key(secret_chat::key_size(), 0);

    TGLC_bn_bn2bin(r.get(), (key.data() + (secret_chat::key_size() - TGLC_bn_num_bytes(r.get()))));
    set_key(key.data());

    if (key_fingerprint() != m_temp_key_fingerprint) {
        TGL_WARNING("key fingerprint mismatch (my 0x" << std::hex
                << (uint64_t)key_fingerprint()
                << "x 0x" << static_cast<uint64_t>(m_temp_key_fingerprint) << "x)");
        return false;
    }
    m_temp_key_fingerprint = 0;
    return true;
}

void secret_chat::set_dh_params(int32_t root, unsigned char* prime, int32_t version)
{
    auto ua = m_user_agent.lock();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        return;
    }

    m_encr_root = root;
    set_encr_prime(prime, 256);
    m_encr_param_version = version;

    auto res = tglmp_check_DH_params(ua->bn_ctx()->ctx, encr_prime_bn()->bn, encr_root());
    TGL_ASSERT_UNUSED(res, res >= 0);
}

void secret_chat::set_state(const tgl_secret_chat_state& new_state)
{
    if (m_state == tgl_secret_chat_state::waiting && new_state == tgl_secret_chat_state::ok) {
        if (create_keys_end()) {
            m_state = new_state;
        } else {
            m_state = tgl_secret_chat_state::deleted;
        }
    } else {
        m_state = new_state;
    }
}

void secret_chat::message_received(const secret_message& m,
        const std::shared_ptr<tgl_unconfirmed_secret_message>& unconfirmed_message)
{
    const std::shared_ptr<class message>& message = m.message;
    if (!message) {
        return;
    }

    message->set_unread(true);

    int32_t raw_in_seq_no = m.raw_in_seq_no;
    int32_t raw_out_seq_no = m.raw_out_seq_no;

    TGL_DEBUG("secret message received: in_seq_no = " << raw_in_seq_no / 2 << " out_seq_no = " << raw_out_seq_no / 2);

    if (raw_in_seq_no >= 0 && raw_out_seq_no >= 0) {
        if ((raw_out_seq_no & 1) != 1 - (admin_id() == m_our_id.peer_id) ||
            (raw_in_seq_no & 1) != (admin_id() == m_our_id.peer_id)) {
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

            if (message->action() && message->action()->type() == tgl_message_action_type::resend) {
                // We have to make a special case here for resend message because otherwise we may
                // end up with a deadlock where both sides are requesting resend but the resend will
                // never get processed because of a hole ahead of it.
                auto action = std::static_pointer_cast<tgl_message_action_resend>(message->action());
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

void secret_chat::load_unconfirmed_incoming_messages_if_needed()
{
    if (m_unconfirmed_incoming_messages_loaded) {
        return;
    }

    auto ua = m_user_agent.lock();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        return;
    }

    m_unconfirmed_incoming_messages_loaded = true;
    auto storage = ua->unconfirmed_secret_message_storage();
    m_unconfirmed_incoming_messages.clear();
    auto unconfirmed_messages = storage->load_messages_by_out_seq_no(id().peer_id, in_seq_no() + 1, -1, false);
    tgl_peer_id_t from_id = tgl_peer_id_t(tgl_peer_type::user, user_id());
    for (const auto& unconfirmed_message: unconfirmed_messages) {
        const auto& blobs = unconfirmed_message->blobs();
        secret_message m;
        m.raw_in_seq_no = unconfirmed_message->in_seq_no() * 2 + (admin_id() != m_our_id.peer_id);
        m.raw_out_seq_no = unconfirmed_message->out_seq_no() * 2 + (admin_id() == m_our_id.peer_id);
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
        m_unconfirmed_incoming_messages.emplace(unconfirmed_message->out_seq_no(), m);
    }
}

void secret_chat::load_unconfirmed_outgoing_messages_if_needed()
{
    if (m_unconfirmed_outgoing_messages_loaded) {
        return;
    }

    auto ua = m_user_agent.lock();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        return;
    }

    m_unconfirmed_outgoing_messages_loaded = true;
    auto storage = ua->unconfirmed_secret_message_storage();
    m_unconfirmed_outgoing_seq_numbers.clear();
    m_unconfirmed_outgoing_message_ids.clear();
    auto unconfirmed_messages = storage->load_messages_by_out_seq_no(id().peer_id, 0, out_seq_no(), true);
    for (const auto& unconfirmed_message: unconfirmed_messages) {
        if (unconfirmed_message->blobs().empty()) {
            continue;
        }
        m_unconfirmed_outgoing_seq_numbers.emplace(unconfirmed_message->message_id(), unconfirmed_message->out_seq_no());
        m_unconfirmed_outgoing_message_ids.emplace(unconfirmed_message->out_seq_no(), unconfirmed_message->message_id());
    }
}

void secret_chat::queue_unconfirmed_incoming_message(const secret_message& m,
        const std::shared_ptr<tgl_unconfirmed_secret_message>& unconfirmed_message)
{
    auto ua = m_user_agent.lock();
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
    m_unconfirmed_incoming_messages.emplace(out_seq_no, m);

    if (!m_skip_hole_timer) {
        std::weak_ptr<secret_chat> weak_secret_chat(shared_from_this());
        m_skip_hole_timer = ua->timer_factory()->create_timer([weak_secret_chat] {
            auto sc = weak_secret_chat.lock();
            if (!sc) {
                return;
            }
            if (sc->m_unconfirmed_incoming_messages.size()) {
                std::vector<secret_message> messages;
                auto it = sc->m_unconfirmed_incoming_messages.begin();
                int32_t seq_no = it->first;
                while (it != sc->m_unconfirmed_incoming_messages.end() && seq_no == it->first) {
                    messages.push_back(it->second);
                    ++it;
                    seq_no++;
                }
                TGL_DEBUG("skipped hole range [" << sc->in_seq_no() << "," << seq_no - 1 << "] with " << messages.size() << " messages");
                sc->process_messages(messages);
                sc->m_unconfirmed_incoming_messages.erase(sc->m_unconfirmed_incoming_messages.begin(), it);
            }
            sc->m_fill_hole_timer->start(REQUEST_RESEND_DELAY);
        });
    }

    if (!m_fill_hole_timer) {
        std::weak_ptr<secret_chat> weak_secret_chat(shared_from_this());
        m_fill_hole_timer = ua->timer_factory()->create_timer([weak_secret_chat] {
            auto sc = weak_secret_chat.lock();
            if (!sc) {
                return;
            }
            auto hole = sc->first_hole();
            int32_t hole_start = hole.first;
            int32_t hole_end = hole.second;
            if (hole_start >= 0 && hole_end >= 0) {
                assert(hole_end >= hole_start);
                assert(hole_start == sc->in_seq_no());
                sc->request_resend_messages(hole_start, hole_end);
                if (sc->m_qos == secret_chat::qos::real_time) {
                    sc->m_skip_hole_timer->start(HOLE_TTL);
                }
            }
        });
    }

    m_fill_hole_timer->start(REQUEST_RESEND_DELAY);
}

std::vector<secret_message>
secret_chat::dequeue_unconfirmed_incoming_messages(const secret_message& m)
{
    assert(m.raw_out_seq_no >= 0);
    assert(m.raw_out_seq_no >= 0);

    std::vector<secret_message> messages;

    int32_t out_seq_no = m.raw_out_seq_no / 2;
    m_unconfirmed_incoming_messages.emplace(out_seq_no, m);
    int32_t in_seq_no = this->in_seq_no();
    auto it = m_unconfirmed_incoming_messages.begin();
    while (it != m_unconfirmed_incoming_messages.end() && it->first == in_seq_no) {
        in_seq_no++;
        messages.push_back(it->second);
        m_unconfirmed_incoming_messages.erase(it);
        it = m_unconfirmed_incoming_messages.begin();
    }

    if (messages.size() > 1) {
        TGL_DEBUG("after received a message with out_seq_no " << out_seq_no << " we dequeued " << messages.size() - 1 << " messages, "
                << m_unconfirmed_incoming_messages.size() << " out of order messages left");
    }

    return messages;
}

void secret_chat::queue_unconfirmed_outgoing_message(
        const std::shared_ptr<tgl_unconfirmed_secret_message>& unconfirmed_message)
{
    if (auto ua = m_user_agent.lock()) {
        auto storage = ua->unconfirmed_secret_message_storage();
        storage->store_message(unconfirmed_message);
    }
    m_unconfirmed_outgoing_seq_numbers.emplace(unconfirmed_message->message_id(), unconfirmed_message->out_seq_no());
    m_unconfirmed_outgoing_message_ids.emplace(unconfirmed_message->out_seq_no(), unconfirmed_message->message_id());
}

std::pair<int32_t, int32_t>
secret_chat::first_hole() const
{
    if (m_unconfirmed_incoming_messages.empty()) {
        return std::make_pair(-1, -1);
    }

    int32_t in_seq_no = this->in_seq_no();
    auto it = m_unconfirmed_incoming_messages.begin();
    assert(it->first > in_seq_no);
    return std::make_pair(in_seq_no, it->first - 1);
}

void secret_chat::process_messages(const std::vector<secret_message>& messages)
{
    auto ua = m_user_agent.lock();
    if (messages.empty() || !ua) {
        return;
    }

    std::vector<std::shared_ptr<tgl_message>> messages_to_deliver;
    for (const auto& m: messages) {
        const auto& message = m.message;
        if (!message) {
            continue;
        }

        if (m.raw_out_seq_no >= 0 && message->from_id().peer_id != m_our_id.peer_id) {
            message->set_sequence_number(m.raw_out_seq_no / 2);
        }
        auto action_type = message->action() ? message->action()->type() : tgl_message_action_type::none;
        if (action_type == tgl_message_action_type::none) {
            messages_to_deliver.push_back(message);
        } else if (action_type == tgl_message_action_type::request_key) {
            auto action = std::static_pointer_cast<tgl_message_action_request_key>(message->action());
            if (exchange_state() == tgl_secret_chat_exchange_state::none
                    || (exchange_state() == tgl_secret_chat_exchange_state::requested && exchange_id() > action->exchange_id )) {
                accept_key_exchange(action->exchange_id, action->g_a);
            } else {
                TGL_WARNING("secret_chat exchange: incorrect state (received request, state = " << exchange_state() << ")");
            }
        } else if (action_type == tgl_message_action_type::accept_key) {
            auto action = std::static_pointer_cast<tgl_message_action_accept_key>(message->action());
            if (exchange_state() == tgl_secret_chat_exchange_state::requested && exchange_id() == action->exchange_id) {
                commit_key_exchange(action->g_a);
            } else {
                TGL_WARNING("secret_chat exchange: incorrect state (received accept, state = " << exchange_state() << ")");
            }
        } else if (action_type == tgl_message_action_type::commit_key) {
            auto action = std::static_pointer_cast<tgl_message_action_commit_key>(message->action());
            if (exchange_state() == tgl_secret_chat_exchange_state::accepted && exchange_id() == action->exchange_id) {
                confirm_key_exchange(1);
            } else {
                TGL_WARNING("secret_chat exchange: incorrect state (received commit, state = " << exchange_state() << ")");
            }
        } else if (action_type == tgl_message_action_type::abort_key) {
            auto action = std::static_pointer_cast<tgl_message_action_abort_key>(message->action());
            if (exchange_state() != tgl_secret_chat_exchange_state::none && exchange_id() == action->exchange_id) {
                abort_key_exchange();
            } else {
                TGL_WARNING("secret_chat exchange: incorrect state (received abort, state = " << exchange_state() << ")");
            }
        } else if (action_type == tgl_message_action_type::notify_layer) {
            auto action = std::static_pointer_cast<tgl_message_action_notify_layer>(message->action());
            set_layer(action->layer);
        } else if (action_type == tgl_message_action_type::set_message_ttl) {
            auto action = std::static_pointer_cast<tgl_message_action_set_message_ttl>(message->action());
            set_ttl(action->ttl);
        } else if (action_type == tgl_message_action_type::delete_messages) {
            auto action = std::static_pointer_cast<tgl_message_action_delete_messages>(message->action());
            incoming_messages_deleted(action->msg_ids);
        } else if (action_type == tgl_message_action_type::resend) {
            auto action = std::static_pointer_cast<tgl_message_action_resend>(message->action());
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
        ua->callback()->new_messages(messages_to_deliver);
    }

    if (peer_raw_in_seq_no >= 0 && peer_raw_out_seq_no >= 0) {
        auto storage = ua->unconfirmed_secret_message_storage();
        int32_t peer_in_seq_no = peer_raw_in_seq_no / 2;
        int32_t peer_out_seq_no = peer_raw_out_seq_no / 2;
        if (peer_in_seq_no > 0) {
            auto end = m_unconfirmed_outgoing_message_ids.lower_bound(peer_in_seq_no);
            for (auto it = m_unconfirmed_outgoing_message_ids.begin(); it != end; ++it) {
                m_unconfirmed_outgoing_seq_numbers.erase(it->second);
            }
            m_unconfirmed_outgoing_message_ids.erase(m_unconfirmed_outgoing_message_ids.begin(), end);
            storage->remove_messages_by_out_seq_no(id().peer_id, 0, peer_in_seq_no - 1, true);
        }
        storage->remove_messages_by_out_seq_no(id().peer_id, 0, peer_out_seq_no, false);
    }
}

bool secret_chat::decrypt_message(int32_t*& decr_ptr, int32_t* decr_end)
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

std::shared_ptr<message> secret_chat::fetch_message(const tl_ds_encrypted_message* DS_EM)
{
    return fetch_message(DS_EM, false).first.message;
}

std::pair<secret_message, std::shared_ptr<tgl_unconfirmed_secret_message>>
secret_chat::fetch_message(const tl_ds_encrypted_message* DS_EM, bool construct_unconfirmed_message)
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
secret_chat::fetch_message(tgl_in_buffer& in, const tgl_peer_id_t& from_id, int64_t message_id,
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

        m.message = std::make_shared<message>(shared_from_this(),
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
            m.message->set_sequence_number(m.raw_out_seq_no / 2);
        } else {
            m.message->set_sequence_number(m.raw_in_seq_no / 2);
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

        m.message = std::make_shared<message>(shared_from_this(),
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

    if (construct_unconfirmed_message && unconfirmed_message && file && m.message->media()
            && m.message->media()->type() == tgl_message_media_type::document
            && std::static_pointer_cast<tgl_message_media_document>(m.message->media())->document->is_encrypted()) {
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

std::shared_ptr<message> secret_chat::construct_message(const tgl_peer_id_t& from_id,
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

void secret_chat::imbue_encrypted_message(const tl_ds_encrypted_message* DS_EM)
{
    if (!DS_EM) {
        return;
    }

    auto message_pair = fetch_message(DS_EM, true);
    message_received(message_pair.first, message_pair.second);
}

void secret_chat::incoming_messages_deleted(const std::vector<int64_t>& message_ids)
{
    auto ua = m_user_agent.lock();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        return;
    }

    load_unconfirmed_incoming_messages_if_needed();

    const auto& storage = ua->unconfirmed_secret_message_storage();
    for (int64_t id : message_ids) {
        bool is_unconfirmed = false;
        for (auto& it: m_unconfirmed_incoming_messages) {
            const auto& message = it.second.message;
            if (message && message->id() == id) {
               auto unconfirmed_message = unconfirmed_secret_message::create_default_impl(
                        id,
                        message->date(),
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

void secret_chat::send_message(const std::shared_ptr<class message>& message,
        const std::function<void(bool, const std::shared_ptr<class message>&)>& callback)
{
    auto ua = m_user_agent.lock();
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

    assert(message->id());

    std::shared_ptr<query> q;

    load_unconfirmed_outgoing_messages_if_needed();
    const auto& it = m_unconfirmed_outgoing_seq_numbers.find(message->id());
    if (it != m_unconfirmed_outgoing_seq_numbers.end()) {
        auto queries = query_messages_send_encrypted_base::create_by_out_seq_no(shared_from_this(), it->second, it->second);
        if (queries.size() == 1) {
            q = *(queries.begin());
        }
    }

    if (!q) {
        if (message->is_service()) {
            if (!message->action()) {
                if (callback) {
                    TGL_WARNING("we can't send a service message which doesn't have an action");
                    callback(true, nullptr);
                }
                return;
            }
            q = std::make_shared<query_messages_send_encrypted_action>(*ua, shared_from_this(), message, callback);
        } else {
            q = std::make_shared<query_messages_send_encrypted_message>(*ua, shared_from_this(), message, callback);
        }
    }

    ua->callback()->new_messages({message});
    q->execute(ua->active_client());
}

void secret_chat::send_action(const tl_ds_decrypted_message_action& action,
        int64_t message_id,
        const std::function<void(bool, const std::shared_ptr<message>&)>& callback)
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

    auto m = std::make_shared<message>(shared_from_this(),
            message_id,
            m_our_id,
            &date,
            std::string(),
            nullptr,
            &action,
            nullptr);
    m->set_pending(true).set_unread(true);
    send_message(m, callback);
}

void secret_chat::send_location(double latitude, double longitude,
        const std::function<void(bool success, const std::shared_ptr<message>&)>& callback)
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
    auto m = std::make_shared<message>(shared_from_this(),
            message_id,
            m_our_id,
            &date,
            std::string(),
            &TDSM,
            nullptr,
            nullptr);
    m->set_unread(true).set_pending(true);
    send_message(m, callback);
}

void secret_chat::send_layer()
{
    struct tl_ds_decrypted_message_action action;
    memset(&action, 0, sizeof(action));
    action.magic = CODE_decrypted_message_action_notify_layer;
    int layer = TGL_ENCRYPTED_LAYER;
    action.layer = &layer;

    std::weak_ptr<user_agent> weak_ua = m_user_agent;
    send_action(action, 0, [=](bool success, const std::shared_ptr<message>&) {
        if (success) {
            if (auto ua = weak_ua.lock()) {
                ua->callback()->secret_chat_update(shared_from_this());
            }
        }
    });
}

void secret_chat::mark_messages_read(int32_t max_time,
        const std::function<void(bool, const std::shared_ptr<message>&)>& callback)
{
    auto ua = m_user_agent.lock();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        if (callback) {
            callback(false, nullptr);
        }
        return;
    }

    auto q = std::make_shared<query_mark_read_encr>(*ua, shared_from_this(), max_time, callback);
    q->out_i32(CODE_messages_read_encrypted_history);
    q->out_i32(CODE_input_encrypted_chat);
    q->out_i32(id().peer_id);
    q->out_i64(id().access_hash);
    q->out_i32(max_time); // FIXME
    q->execute(ua->active_client());
}

void secret_chat::set_deleted()
{
    set_state(tgl_secret_chat_state::deleted);
    if (auto ua = m_user_agent.lock()) {
        ua->callback()->secret_chat_update(shared_from_this());
    }
}

void secret_chat::delete_message(int64_t message_id,
        const std::function<void(bool, const std::shared_ptr<message>&)>& callback)
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

void secret_chat::request_resend_messages(int32_t start_seq_no, int32_t end_seq_no)
{
    TGL_DEBUG("requesting to resend range [" << start_seq_no << "," << end_seq_no << "]");

    tl_ds_decrypted_message_action action;
    action.magic = CODE_decrypted_message_action_resend;
    action.start_seq_no = &start_seq_no;
    action.end_seq_no = &end_seq_no;

    send_action(action, 0, nullptr);
}

void secret_chat::resend_messages(int32_t start_seq_no, int32_t end_seq_no)
{
    if (start_seq_no < 0 || end_seq_no < 0 || end_seq_no < start_seq_no) {
        return;
    }

    auto ua = m_user_agent.lock();
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

void secret_chat::request_key_exchange()
{
    assert(false);
}

void secret_chat::accept_key_exchange(
        int64_t exchange_id, const std::vector<unsigned char>& ga)
{
    assert(false);
}

void secret_chat::confirm_key_exchange(int sen_nop)
{
    assert(false);
}

void secret_chat::commit_key_exchange(const std::vector<unsigned char>& gb)
{
    assert(false);
}

void secret_chat::abort_key_exchange()
{
    assert(false);
}

}
}
