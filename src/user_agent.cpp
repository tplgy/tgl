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

    Copyright Vitaly Valtman 2014-2015
    Copyright Topology LP 2016-2017
*/

#include "user_agent.h"

#include "tools.h"
#include "mtproto-common.h"
#include "mtproto_client.h"
#include "structures.h"
#include "tgl_rsa_key.h"
#include "tools.h"
#include "crypto/tgl_crypto_bn.h"
#include "crypto/tgl_crypto_rsa_pem.h"
#include "crypto/tgl_crypto_sha.h"
#include "tgl/tgl_online_status_observer.h"
#include "tgl/tgl_query_api.h"
#include "tgl/tgl_secret_chat.h"
#include "tgl/tgl_timer.h"
#include "tgl/tgl_unconfirmed_secret_message_storage.h"
#include "tgl/tgl_update_callback.h"
#include "tgl_secret_chat_private.h"
#include "tgl_session.h"
#include "transfer_manager.h"
#include "query/queries.h"
#include "query/query.h"

#include <assert.h>
#include <stdlib.h>

constexpr int MAX_DC_ID = 10;
constexpr int32_t TG_APP_ID = 10534;
constexpr const char* TG_APP_HASH = "844584f2b1fd2daecee726166dcc1ef8";

std::shared_ptr<tgl_user_agent> tgl_user_agent::create(
        const std::vector<std::string>& rsa_keys,
        const std::string& download_dir,
        int app_id,
        const std::string& app_hash,
        const std::string& app_version,
        const std::string& device_model,
        const std::string& system_version,
        const std::string& lang_code)
{
    auto ua = std::make_shared<user_agent>();

    ua->m_transfer_manager = std::make_shared<class transfer_manager>(ua, download_dir);
    ua->m_app_id = app_id;
    ua->m_app_hash = app_hash;
    ua->m_app_version = app_version;
    ua->m_device_model = device_model;
    ua->m_system_version = system_version;
    ua->m_lang_code = lang_code;
    ua->m_temp_key_expire_time = 7200; // seconds

    tgl_prng_seed(nullptr, 0);

    for (const auto& raw_key: rsa_keys) {
        ua->add_rsa_key(raw_key);
    }

    bool ok = false;
    for (const auto& key: ua->rsa_keys()) {
        if (key->load()) {
            ok = true;
        } else {
            TGL_WARNING("can not load key " << key->public_key_string());
        }
    }

    if (!ok) {
        TGL_ERROR("no public keys found");
        return nullptr;
    }

    if (!ua->m_app_id) {
        ua->m_app_id = TG_APP_ID;
        ua->m_app_hash = TG_APP_HASH;
    }

    return ua;
}

user_agent::user_agent()
    : m_online_status(tgl_online_status::not_online)
    , m_date(0)
    , m_pts(0)
    , m_qts(0)
    , m_seq(0)
    , m_app_id(0)
    , m_temp_key_expire_time(0)
    , m_is_started(false)
    , m_test_mode(false)
    , m_pfs_enabled(false)
    , m_ipv6_enabled(false)
    , m_diff_locked(false)
    , m_password_locked(false)
    , m_phone_number_input_locked(false)
    , m_bn_ctx(std::make_unique<tgl_bn_context>(TGLC_bn_ctx_new()))
    , m_updater(std::make_unique<class updater>(*this))
{
}

void user_agent::shut_down()
{
    m_is_started = false;

    m_online_status_observers.clear();
    m_clients.clear();
    m_active_queries.clear();
    m_secret_chats.clear();
}

void user_agent::delete_query(int64_t id)
{
    std::shared_ptr<query> q = get_query(id);
    if (!q) {
        return;
    }

    q->clear_timers();

    if (id) {
        remove_query(q);
    }
}

void user_agent::set_dc_auth_key(int dc_id, const char* key, size_t key_length)
{
    assert(dc_id > 0 && dc_id <= MAX_DC_ID);

    assert(key);
    assert(key_length == 256);
    if (!key || key_length != 256) {
        return;
    }

    auto client = m_clients[dc_id];
    client->set_auth_key(reinterpret_cast<const unsigned char*>(key), key_length);
    m_callback->dc_updated(client);
}

void user_agent::set_our_id(int id)
{
    if (m_our_id.peer_id == id) {
        return;
    }
    m_our_id.peer_id = id;
    m_our_id.peer_type = tgl_peer_type::user;
    assert(our_id().peer_id > 0);
    m_callback->our_id(our_id().peer_id);
}

void user_agent::set_dc_option(bool is_v6, int id, const std::string& ip, int port)
{
    if (id < 0) {
        return;
    }

    if (static_cast<size_t>(id) >= m_clients.size()) {
        m_clients.resize(id + 1, nullptr);
    }

    if (!m_clients[id]) {
        m_clients[id] = allocate_client(id);
        if (pfs_enabled()) {
          //dc->ev = user_agent::instance()->timer_factory()->create_timer(std::bind(&regen_temp_key_gw, DC));
          //dc->ev->start(0);
        }
    }
    if (is_v6) {
        m_clients[id]->add_ipv6_option(ip, port);
    } else {
        m_clients[id]->add_ipv4_option(ip, port);
    }
}

void user_agent::set_dc_logged_in(int dc_id)
{
    TGL_DEBUG("set signed " << dc_id);
    assert(dc_id > 0 && dc_id <= MAX_DC_ID);
    auto client = m_clients[dc_id];
    client->set_logged_in();
    m_callback->dc_updated(client);
}

void user_agent::set_active_dc(int dc_id)
{
    if (m_active_client && m_active_client->id() == dc_id) {
        return;
    }
    TGL_DEBUG("change active DC to " << dc_id);
    assert(dc_id > 0 && dc_id <= MAX_DC_ID);
    m_active_client = m_clients[dc_id];
    m_callback->active_dc_changed(dc_id);
}

void user_agent::set_qts(int32_t qts, bool force)
{
    if (is_diff_locked()) {
        return;
    }

    if (qts <= m_qts && !force) {
        return;
    }

    m_qts = qts;
    m_callback->qts_changed(qts);
}

void user_agent::set_pts(int32_t pts, bool force)
{
    if (is_diff_locked() && !force) {
        return;
    }

    if (pts <= m_pts && !force) {
        return;
    }

    m_pts = pts;
    m_callback->pts_changed(pts);
}

void user_agent::set_date(int64_t date, bool force)
{
    if (is_diff_locked() && !force) {
        return;
    }

    if (date <= m_date && !force) {
        return;
    }

    m_date = date;
    m_callback->date_changed(date);
}

void user_agent::set_seq(int32_t seq)
{
    if (is_diff_locked()) {
        return;
    }

    if (seq <= m_seq) {
        return;
    }

    m_seq = seq;
}

void user_agent::reset_authorization()
{
    for (const auto& client: m_clients) {
        if (client) {
            client->reset_authorization();
            client->set_logged_in(false);
        }
    }

    m_qts = 0;
    m_pts = 0;
    m_date = 0;
    m_seq = 0;
}

void user_agent::add_rsa_key(const std::string& key)
{
    m_rsa_keys.push_back(std::unique_ptr<tgl_rsa_key>(new tgl_rsa_key(key)));
}

int32_t user_agent::create_secret_chat_id() const
{
    int32_t chat_id = tgl_random<int32_t>();
    while (secret_chat_for_id(chat_id)) {
        chat_id = tgl_random<int32_t>();
    }
    return chat_id;
}

std::shared_ptr<tgl_secret_chat> user_agent::allocate_secret_chat(const tgl_input_peer_t& chat_id, int32_t user_id)
{
    if (m_secret_chats.find(chat_id.peer_id) != m_secret_chats.end()) {
        TGL_WARNING("can't allocate a secret chat with exisiting id " << chat_id.peer_id);
        return nullptr;
    }

    auto d = std::make_unique<tgl_secret_chat_private>();
    d->m_user_agent = std::weak_ptr<user_agent>(shared_from_this());
    d->m_id = chat_id;
    d->m_user_id = user_id;
    d->m_our_id = m_our_id;
    auto secret_chat = std::make_shared<tgl_secret_chat>(std::move(d));
    m_secret_chats[chat_id.peer_id] = secret_chat;

    return secret_chat;
}

std::shared_ptr<tgl_secret_chat> user_agent::load_secret_chat(int32_t chat_id, int64_t access_hash, int32_t user_id,
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
    if (m_secret_chats.find(chat_id) != m_secret_chats.end()) {
        TGL_WARNING("can't load a secret chat with an id " << chat_id << " used by another secret chat");
        return nullptr;
    }

    auto d = std::make_unique<tgl_secret_chat_private>();
    d->m_user_agent = std::weak_ptr<user_agent>(shared_from_this());
    d->m_id = tgl_input_peer_t(tgl_peer_type::enc_chat, chat_id, access_hash);
    d->m_user_id = user_id;
    d->m_our_id = m_our_id;
    d->m_exchange_id = exchange_id;
    d->m_admin_id = admin;
    d->m_date = date;
    d->m_ttl = ttl;
    d->m_layer = layer;
    d->m_in_seq_no = in_seq_no;
    d->m_out_seq_no = out_seq_no;
    d->m_encr_root = encr_root;
    d->m_encr_param_version = encr_param_version;
    d->m_state = state;
    d->m_exchange_state = exchange_state;
    assert(key_length == tgl_secret_chat::key_size());
    d->set_key(key);
    d->set_encr_prime(encr_prime, encr_prime_length);
    d->set_g_key(g_key, g_key_length);
    d->set_exchange_key(exchange_key, exchange_key_length);
    auto secret_chat = std::make_shared<tgl_secret_chat>(std::move(d));
    m_secret_chats[chat_id] = secret_chat;

    return secret_chat;
}

std::shared_ptr<tgl_secret_chat> user_agent::secret_chat_for_id(int chat_id) const
{
    auto secret_chat_it = m_secret_chats.find(chat_id);
    if (secret_chat_it == m_secret_chats.end()) {
        return nullptr;
    }
    return secret_chat_it->second;
}

void user_agent::add_query(const std::shared_ptr<query>& q)
{
    auto id = q->msg_id();
    assert(id);
    auto inserted_iterator_pair = m_active_queries.emplace(id, q);
    if (inserted_iterator_pair.second) {
        q->client()->increase_active_queries();
    } else {
        inserted_iterator_pair.first->second = q;
    }
}

std::shared_ptr<query> user_agent::get_query(int64_t id) const
{
    assert(id);
    auto it = m_active_queries.find(id);
    if (it == m_active_queries.end()) {
        return nullptr;
    }
    return it->second;
}

void user_agent::remove_query(const std::shared_ptr<query>& q)
{
    auto id = q->msg_id();
    assert(id);
    auto it = m_active_queries.find(id);
    if (it != m_active_queries.end()) {
        m_active_queries.erase(it);
        q->client()->decrease_active_queries();
    }
}

void user_agent::remove_all_queries()
{
    m_active_queries.clear();
}

std::shared_ptr<mtproto_client> user_agent::client_at(int id) const
{
    if (static_cast<size_t>(id) >= m_clients.size()) {
        return nullptr;
    }

    return m_clients[id];
}

std::shared_ptr<mtproto_client> user_agent::allocate_client(int id)
{
    if (static_cast<size_t>(id) >= m_clients.size()) {
        m_clients.resize(id + 1, nullptr);
    }

    assert(!m_clients[id]);

    std::shared_ptr<mtproto_client> client = std::make_shared<mtproto_client>(shared_from_this(), id);
    m_clients[id] = client;

    return client;
}

void user_agent::state_lookup_timeout()
{
    lookup_state();

    if (m_state_lookup_timer) {
        m_state_lookup_timer->start(3600);
    }
}

void user_agent::set_online_status(tgl_online_status status)
{
    if (status == m_online_status) {
        return;
    }

    TGL_DEBUG("setting online status to " << status
            << " (previous: " << m_online_status << ")");
    m_online_status = status;
    std::vector<std::weak_ptr<tgl_online_status_observer>> dead_weak_observers;
    for (const auto& weak_observer: m_online_status_observers) {
        if (auto observer = weak_observer.lock()) {
            observer->on_online_status_changed(status);
        } else {
            dead_weak_observers.push_back(weak_observer);
        }
    }

    for (const auto& dead_weak_observer: dead_weak_observers) {
        m_online_status_observers.erase(dead_weak_observer);
    }
}

std::shared_ptr<tgl_dc> user_agent::active_dc() const
{
    return m_active_client;
}

void user_agent::fetch_dc_option(const tl_ds_dc_option* DS_DO)
{
    if (DS_BOOL(DS_DO->media_only)) { // We do not support media only ip addresses yet
        return;
    }

    set_dc_option(DS_BOOL(DS_DO->ipv6),
            DS_LVAL(DS_DO->id),
            DS_STDSTR(DS_DO->ip_address),
            DS_LVAL(DS_DO->port));
}

void user_agent::add_online_status_observer(const std::weak_ptr<tgl_online_status_observer>& observer)
{
    m_online_status_observers.insert(observer);
}

void user_agent::remove_online_status_observer(const std::weak_ptr<tgl_online_status_observer>& observer)
{
    m_online_status_observers.erase(observer);
}

void user_agent::set_unconfirmed_secret_message_storage(
        const std::shared_ptr<tgl_unconfirmed_secret_message_storage>& storage)
{
    m_unconfirmed_secret_message_storage = storage;
}

const std::shared_ptr<tgl_unconfirmed_secret_message_storage>
user_agent::unconfirmed_secret_message_storage() const
{
    return m_unconfirmed_secret_message_storage;
}

void user_agent::clear_all_locks()
{
    m_diff_locked = false;
    m_password_locked = false;
    m_phone_number_input_locked = false;
}
