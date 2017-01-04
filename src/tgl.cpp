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
    Copyright Topology LP 2016
*/

#include "tgl/tgl.h"

#include "tools.h"
#include "mtproto_client.h"
#include "structures.h"
#include "tgl_rsa_key.h"
#include "tools.h"
#include "crypto/tgl_crypto_bn.h"
#include "crypto/tgl_crypto_rsa_pem.h"
#include "crypto/tgl_crypto_sha.h"
#include "tgl/tgl_online_status_observer.h"
#include "tgl/tgl_queries.h"
#include "tgl/tgl_update_callback.h"
#include "tgl/tgl_secret_chat.h"
#include "tgl/tgl_transfer_manager.h"
#include "tgl/tgl_timer.h"
#include "tgl_session.h"
#include "queries.h"

#include <assert.h>
#include <stdlib.h>

constexpr int MAX_DC_ID = 10;
constexpr int32_t TG_APP_ID = 10534;
constexpr const char* TG_APP_HASH = "844584f2b1fd2daecee726166dcc1ef8";

std::unique_ptr<tgl_state> tgl_state::s_instance;

tgl_state::tgl_state()
    : m_online_status(tgl_online_status::not_online)
    , m_app_id(0)
    , m_error_code(0)
    , m_temp_key_expire_time(0)
    , m_pts(0)
    , m_qts(0)
    , m_date(0)
    , m_seq(0)
    , m_is_started(false)
    , m_test_mode(false)
    , m_enable_pfs(false)
    , m_ipv6_enabled(false)
    , m_diff_locked(false)
    , m_password_locked(false)
    , m_phone_number_input_locked(false)
    , m_our_id()
    , m_bn_ctx(new tgl_bn_context(TGLC_bn_ctx_new()))
    , m_online_status_observers()
{
}

tgl_state* tgl_state::instance()
{
    if (!s_instance) {
        s_instance.reset(new tgl_state);
    }
    return s_instance.get();
}

void tgl_state::reset()
{
    s_instance.reset();
}

void tgl_state::set_dc_auth_key(int dc_id, const char* key, size_t key_length)
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

void tgl_state::set_our_id(int id)
{
    if (m_our_id.peer_id == id) {
        return;
    }
    m_our_id.peer_id = id;
    m_our_id.peer_type = tgl_peer_type::user;
    assert(our_id().peer_id > 0);
    m_callback->our_id(our_id().peer_id);
}

void tgl_state::set_dc_option(bool is_v6, int id, const std::string& ip, int port)
{
    if (id < 0) {
        return;
    }

    if (static_cast<size_t>(id) >= m_clients.size()) {
        m_clients.resize(id + 1, nullptr);
    }

    if (!m_clients[id]) {
        m_clients[id] = allocate_client(id);
        if (tgl_state::instance()->pfs_enabled()) {
          //dc->ev = tgl_state::instance()->timer_factory()->create_timer(std::bind(&regen_temp_key_gw, DC));
          //dc->ev->start(0);
        }
    }
    if (is_v6) {
        m_clients[id]->add_ipv6_option(ip, port);
    } else {
        m_clients[id]->add_ipv4_option(ip, port);
    }
}

void tgl_state::set_dc_logged_in(int dc_id)
{
    TGL_DEBUG("set signed " << dc_id);
    assert(dc_id > 0 && dc_id <= MAX_DC_ID);
    auto client = m_clients[dc_id];
    client->set_logged_in();
    m_callback->dc_updated(client);
}

void tgl_state::set_active_dc(int dc_id)
{
    if (m_active_client && m_active_client->id() == dc_id) {
        return;
    }
    TGL_DEBUG("change active DC to " << dc_id);
    assert(dc_id > 0 && dc_id <= MAX_DC_ID);
    m_active_client = m_clients[dc_id];
    m_callback->active_dc_changed(dc_id);
}

void tgl_state::set_qts(int32_t qts, bool force)
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

void tgl_state::set_pts(int32_t pts, bool force)
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

void tgl_state::set_date(int64_t date, bool force)
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

void tgl_state::set_seq(int32_t seq)
{
    if (is_diff_locked()) {
        return;
    }

    if (seq <= m_seq) {
        return;
    }

    m_seq = seq;
}

void tgl_state::reset_authorization()
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

void tgl_state::add_rsa_key(const std::string& key)
{
    m_rsa_key_list.push_back(std::unique_ptr<tgl_rsa_key>(new tgl_rsa_key(key)));
}

int tgl_state::init(const std::string& download_dir, int app_id, const std::string& app_hash, const std::string& app_version)
{
    m_transfer_manager = std::make_shared<tgl_transfer_manager>(download_dir);
    m_app_id = app_id;
    m_app_hash = app_hash;
    m_app_version = app_version;
    assert(m_timer_factory);
    assert(m_connection_factory);
    if (!m_temp_key_expire_time) {
        m_temp_key_expire_time = 7200; // seconds
    }

    if (tglmp_on_start() < 0) {
        return -1;
    }

    if (!m_app_id) {
        m_app_id = TG_APP_ID;
        m_app_hash = TG_APP_HASH;
    }

    m_state_lookup_timer = m_timer_factory->create_timer(std::bind(&tgl_state::state_lookup_timeout));
    m_state_lookup_timer->start(3600);
    return 0;
}

void tgl_state::set_enable_pfs(bool val)
{
    m_enable_pfs = val;
}

void tgl_state::set_test_mode(bool val)
{
    m_test_mode = val;
}

void tgl_state::set_enable_ipv6(bool val)
{
    m_ipv6_enabled = val;
}

void tgl_state::set_error(const std::string& error, int error_code)
{
    m_error = error;
    m_error_code = error_code;
}

int32_t tgl_state::create_secret_chat_id()
{
    int chat_id = tgl_random<int>();
    while (tgl_state::instance()->secret_chat_for_id(chat_id)) {
        chat_id = tgl_random<int>();
    }
    return chat_id;
}

//std::shared_ptr<tgl_secret_chat> tgl_state::create_secret_chat(int32_t id)
//{
//    int chat_id;
//    if (id) {
//        chat_id = id;
//    } else {
//        chat_id = create_secret_chat_id();
//    }

//    auto secret_chat = std::make_shared<tgl_secret_chat>(chat_id, 0);
//    m_secret_chats[chat_id] = secret_chat;

//    return secret_chat;
//}

std::shared_ptr<tgl_secret_chat> tgl_state::create_secret_chat(const tgl_input_peer_t& chat_id, int32_t user_id)
{
    if (m_secret_chats.find(chat_id.peer_id) != m_secret_chats.end()) {
        return nullptr;
    }

    auto secret_chat = std::make_shared<tgl_secret_chat>(chat_id.peer_id, chat_id.access_hash, user_id);
    m_secret_chats[chat_id.peer_id] = secret_chat;

    return secret_chat;
}

std::shared_ptr<tgl_secret_chat> tgl_state::secret_chat_for_id(int chat_id) const
{
    auto secret_chat_it = m_secret_chats.find(chat_id);
    if (secret_chat_it == m_secret_chats.end()) {
        return nullptr;
    }
    return secret_chat_it->second;
}

void tgl_state::add_secret_chat(const std::shared_ptr<tgl_secret_chat>& secret_chat)
{
    m_secret_chats[secret_chat->id().peer_id] = secret_chat;
}

void tgl_state::add_query(const std::shared_ptr<query>& q)
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

std::shared_ptr<query> tgl_state::get_query(int64_t id) const
{
    assert(id);
    auto it = m_active_queries.find(id);
    if (it == m_active_queries.end()) {
        return nullptr;
    }
    return it->second;
}

void tgl_state::remove_query(const std::shared_ptr<query>& q)
{
    auto id = q->msg_id();
    assert(id);
    auto it = m_active_queries.find(id);
    if (it != m_active_queries.end()) {
        m_active_queries.erase(it);
        q->client()->decrease_active_queries();
    }
}

void tgl_state::remove_all_queries()
{
    m_active_queries.clear();
}

std::shared_ptr<mtproto_client> tgl_state::client_at(int id) const
{
    if (static_cast<size_t>(id) >= m_clients.size()) {
        return nullptr;
    }

    return m_clients[id];
}

std::shared_ptr<mtproto_client> tgl_state::allocate_client(int id)
{
    if (static_cast<size_t>(id) >= m_clients.size()) {
        m_clients.resize(id + 1, nullptr);
    }

    assert(!m_clients[id]);

    std::shared_ptr<mtproto_client> client = std::make_shared<mtproto_client>(id);
    m_clients[id] = client;

    return client;
}

void tgl_state::state_lookup_timeout()
{
    tgl_do_lookup_state();
    if (auto timer = tgl_state::instance()->m_state_lookup_timer) {
        timer->start(3600);
    }
}

void tgl_state::logout()
{
    tgl_do_logout(nullptr);
}

void tgl_state::set_online_status(tgl_online_status status)
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

void tgl_state::connection_status_changed(const std::shared_ptr<tgl_connection>& c, tgl_connection_status status)
{
    const auto& session = m_active_client->session();
    if (session && session->c == c) {
        m_callback->connection_status_changed(status);
    }
}
