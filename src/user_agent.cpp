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

#include "auto/auto.h"
#include "auto/auto-fetch-ds.h"
#include "auto/auto-free-ds.h"
#include "auto/auto-skip.h"
#include "auto/auto-types.h"
#include "auto/constants.h"
#include "channel.h"
#include "chat.h"
#include "crypto/crypto_bn.h"
#include "crypto/crypto_md5.h"
#include "crypto/crypto_rand.h"
#include "crypto/crypto_rsa_pem.h"
#include "crypto/crypto_sha.h"
#include "message.h"
#include "mtproto_client.h"
#include "mtproto_common.h"
#include "mtproto_utils.h"
#include "query/query_add_contacts.h"
#include "query/query_block_or_unblock_user.h"
#include "query/query_channel_get_participant.h"
#include "query/query_channels_get_participants.h"
#include "query/query_channels_set_about.h"
#include "query/query_check_password.h"
#include "query/query_check_username.h"
#include "query/query_create_chat.h"
#include "query/query_delete_contact.h"
#include "query/query_delete_message.h"
#include "query/query_export_card.h"
#include "query/query_export_chat_link.h"
#include "query/query_get_and_check_password.h"
#include "query/query_get_and_set_password.h"
#include "query/query_get_blocked_users.h"
#include "query/query_get_channel_difference.h"
#include "query/query_get_channel_info.h"
#include "query/query_get_chat_info.h"
#include "query/query_get_contacts.h"
#include "query/query_get_dialogs.h"
#include "query/query_get_difference.h"
#include "query/query_get_history.h"
#include "query/query_get_messages.h"
#include "query/query_get_notify_settings.h"
#include "query/query_get_privacy_rules.h"
#include "query/query_get_state.h"
#include "query/query_get_tos.h"
#include "query/query_help_get_config.h"
#include "query/query_import_card.h"
#include "query/query_logout.h"
#include "query/query_lookup_state.h"
#include "query/query_mark_message_read.h"
#include "query/query_messages_accept_encryption.h"
#include "query/query_messages_discard_encryption.h"
#include "query/query_messages_get_dh_config.h"
#include "query/query_messages_request_encryption.h"
#include "query/query_msg_send.h"
#include "query/query_phone_call.h"
#include "query/query_register_device.h"
#include "query/query_resolve_username.h"
#include "query/query_search_contact.h"
#include "query/query_search_message.h"
#include "query/query_send_change_code.h"
#include "query/query_send_code.h"
#include "query/query_send_inline_query_to_bot.h"
#include "query/query_send_messages.h"
#include "query/query_send_typing.h"
#include "query/query_set_phone.h"
#include "query/query_set_profile_name.h"
#include "query/query_sign_in.h"
#include "query/query_unregister_device.h"
#include "query/query_update_notify_settings.h"
#include "query/query_update_status.h"
#include "query/query_user_info.h"
#include "rsa_public_key.h"
#include "secret_chat.h"
#include "session.h"
#include "tgl/tgl_chat.h"
#include "tgl/tgl_log.h"
#include "tgl/tgl_online_status_observer.h"
#include "tgl/tgl_peer_id.h"
#include "tgl/tgl_privacy_rule.h"
#include "tgl/tgl_secure_random.h"
#include "tgl/tgl_timer.h"
#include "tgl/tgl_unconfirmed_secret_message_storage.h"
#include "tgl/tgl_update_callback.h"
#include "tgl/tgl_value.h"
#include "tools.h"
#include "transfer_manager.h"
#include "updater.h"
#include "user.h"

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <string>

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
    auto ua = std::make_shared<tgl::impl::user_agent>();

    ua->m_transfer_manager = std::make_shared<tgl::impl::transfer_manager>(ua, download_dir);
    ua->m_app_id = app_id;
    ua->m_app_hash = app_hash;
    ua->m_app_version = app_version;
    ua->m_device_model = device_model;
    ua->m_system_version = system_version;
    ua->m_lang_code = lang_code;
    ua->m_temp_key_expire_time = 7200; // seconds

    tgl::impl::tgl_prng_seed(nullptr, 0);

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

namespace tgl {
namespace impl {

user_agent::user_agent()
    : m_online_status(tgl_online_status::not_online)
    , m_date(0)
    , m_pts(0)
    , m_qts(0)
    , m_seq(0)
    , m_app_id(0)
    , m_temp_key_expire_time(0)
    , m_bytes_sent(0)
    , m_bytes_received(0)
    , m_is_started(false)
    , m_test_mode(false)
    , m_pfs_enabled(false)
    , m_ipv6_enabled(false)
    , m_diff_locked(false)
    , m_password_locked(false)
    , m_phone_number_input_locked(false)
    , m_device_token_type(0)
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

void user_agent::set_dc_auth_key(int dc_id, const char* key, size_t key_length)
{
    if (dc_id <= 0 || dc_id > MAX_DC_ID) {
        TGL_ERROR("invalid dc id " << dc_id << ", db corrupted?");
        assert(false);
        return;
    }

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

void user_agent::set_dc_logged_in(int dc_id, bool logged_in)
{
    if (dc_id <= 0 || dc_id > MAX_DC_ID) {
        TGL_ERROR("invalid dc id " << dc_id << ", db corrupted?");
        assert(false);
        return;
    }

    TGL_DEBUG("set signed " << dc_id);
    auto client = m_clients[dc_id];
    client->set_logged_in(logged_in);
    m_callback->dc_updated(client);
}

void user_agent::set_active_dc(int dc_id)
{
    if (dc_id <= 0 || dc_id > MAX_DC_ID) {
        TGL_ERROR("invalid dc id " << dc_id << ", db corrupted?");
        assert(false);
        return;
    }

    if (m_active_client && m_active_client->id() == dc_id) {
        return;
    }
    TGL_DEBUG("change active DC to " << dc_id);
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
    m_rsa_keys.push_back(std::unique_ptr<rsa_public_key>(new rsa_public_key(key)));
}

int32_t user_agent::create_secret_chat_id() const
{
    int32_t chat_id = tgl_random<int32_t>();
    while (secret_chat_for_id(chat_id)) {
        chat_id = tgl_random<int32_t>();
    }
    return chat_id;
}

std::shared_ptr<secret_chat> user_agent::allocate_secret_chat(const tgl_input_peer_t& chat_id, int32_t user_id)
{
    if (m_secret_chats.find(chat_id.peer_id) != m_secret_chats.end()) {
        TGL_WARNING("can't allocate a secret chat with exisiting id " << chat_id.peer_id);
        return nullptr;
    }

    auto sc = secret_chat::create(std::weak_ptr<user_agent>(shared_from_this()), chat_id, user_id);

    if (sc) {
        m_secret_chats[chat_id.peer_id] = sc;
    }

    return sc;
}

std::shared_ptr<secret_chat> user_agent::allocate_or_update_secret_chat(const tl_ds_encrypted_chat* DS_EC)
{
    auto sc = secret_chat::create_or_update(std::weak_ptr<user_agent>(shared_from_this()), DS_EC);
    if (sc) {
        m_secret_chats.emplace(sc->id().peer_id, sc);
    }
    return sc;
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

    auto sc = secret_chat::create(std::weak_ptr<user_agent>(shared_from_this()),
            chat_id, access_hash, user_id, admin, date, ttl, layer,
            in_seq_no, out_seq_no,
            encr_root, encr_param_version,
            state, exchange_state, exchange_id,
            key, key_length,
            encr_prime, encr_prime_length,
            g_key, g_key_length,
            exchange_key, exchange_key_length);

    if (sc) {
        m_secret_chats[chat_id] = sc;
    }

    return sc;
}

std::shared_ptr<secret_chat> user_agent::secret_chat_for_id(int chat_id) const
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

void user_agent::send_code(const std::string& phone, const std::function<void(bool, bool, const std::string&)>& callback)
{
    TGL_NOTICE("requesting confirmation code from dc " << active_client()->id());
    auto q = std::make_shared<query_send_code>(callback);
    q->out_i32(CODE_auth_send_code);
    q->out_std_string(phone);
    q->out_i32(0);
    q->out_i32(app_id());
    q->out_std_string(app_hash());
    q->out_string("en");
    q->execute(active_client(), query::execution_option::LOGIN);
}

void user_agent::call_me(const std::string& phone, const std::string& hash,
        const std::function<void(bool)>& callback)
{
    TGL_DEBUG("calling user at phone number: " << phone);

    auto q = std::make_shared<query_phone_call>(callback);
    q->out_header(this);
    q->out_i32(CODE_auth_send_call);
    q->out_std_string(phone);
    q->out_std_string(hash);
    q->execute(active_client(), query::execution_option::LOGIN);
}

void user_agent::send_code_result(const std::string& phone,
        const std::string& hash,
        const std::string& code,
        const std::function<void(bool success, const std::shared_ptr<user>&)>& callback)
{
    auto q = std::make_shared<query_sign_in>(callback);
    q->out_i32(CODE_auth_sign_in);
    q->out_std_string(phone);
    q->out_std_string(hash);
    q->out_std_string(code);
    q->execute(active_client(), query::execution_option::LOGIN);
}

void user_agent::logout()
{
    auto dc = active_client();
    if (dc->is_logging_out()) {
        return;
    }

    if (!dc->is_logged_in()) {
        callback()->logged_out(true);
        return;
    }

    for (const auto& it: secret_chats()) {
        discard_secret_chat(it.second->id(), nullptr);
    }

    std::weak_ptr<user_agent> weak_ua = shared_from_this();
    auto do_logout = [=] {
        auto q = std::make_shared<query_logout>([=](bool success) {
            if (auto ua = weak_ua.lock()) {
                ua->callback()->logged_out(success);
            }
        });
        q->out_i32(CODE_auth_log_out);
        q->execute(dc, query::execution_option::LOGOUT);
    };

    if (m_device_token_type && !m_device_token.empty()) {
        unregister_device(m_device_token_type, m_device_token, [=](bool) {
            do_logout();
        });
    } else {
        do_logout();
    }
}

void user_agent::update_contact_list(const std::function<void(bool, const std::vector<std::shared_ptr<tgl_user>>&)>& callback)
{
    auto q = std::make_shared<query_get_contacts>(callback);
    q->out_i32(CODE_contacts_get_contacts);
    q->out_string("");
    q->execute(active_client());
}

void user_agent::send_text_message(const std::shared_ptr<class message>& message, bool disable_preview,
        const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback)
{
    if (message->to_id().peer_type == tgl_peer_type::enc_chat) {
        assert(false);
        return;
    }

    auto q = std::make_shared<query_msg_send>(message, callback);
    q->out_i32(CODE_messages_send_message);

    unsigned f = (disable_preview ? 2 : 0) | (message->reply_id() ? 1 : 0) | (message->reply_markup() ? 4 : 0) | (message->entities().size() > 0 ? 8 : 0);
    if (message->from_id().peer_type == tgl_peer_type::channel) {
        f |= 16;
    }
    q->out_i32(f);
    q->out_input_peer(this, message->to_id());
    if (message->reply_id()) {
        q->out_i32(message->reply_id());
    }
    q->out_std_string(message->text());
    q->out_i64(message->id());

    if (message->reply_markup()) {
        if (!message->reply_markup()->button_matrix.empty()) {
            q->out_i32(CODE_reply_keyboard_markup);
            q->out_i32(message->reply_markup()->flags);
            q->out_i32(CODE_vector);
            q->out_i32(message->reply_markup()->button_matrix.size());
            for (size_t i = 0; i < message->reply_markup()->button_matrix.size(); ++i) {
                q->out_i32(CODE_keyboard_button_row);
                q->out_i32(CODE_vector);
                q->out_i32(message->reply_markup()->button_matrix[i].size());
                for (size_t j = 0; j < message->reply_markup()->button_matrix[i].size(); ++j) {
                    q->out_i32(CODE_keyboard_button);
                    q->out_std_string(message->reply_markup()->button_matrix[i][j]);
                }
            }
        } else {
            q->out_i32(CODE_reply_keyboard_hide);
        }
    }

    if (message->entities().size() > 0) {
        q->out_i32(CODE_vector);
        q->out_i32(message->entities().size());
        for (size_t i = 0; i < message->entities().size(); i++) {
            auto entity = message->entities()[i];
            switch (entity->type) {
            case tgl_message_entity_type::bold:
                q->out_i32(CODE_message_entity_bold);
                q->out_i32(entity->start);
                q->out_i32(entity->length);
                break;
            case tgl_message_entity_type::italic:
                q->out_i32(CODE_message_entity_italic);
                q->out_i32(entity->start);
                q->out_i32(entity->length);
                break;
            case tgl_message_entity_type::code:
                q->out_i32(CODE_message_entity_code);
                q->out_i32(entity->start);
                q->out_i32(entity->length);
                break;
            case tgl_message_entity_type::text_url:
                q->out_i32(CODE_message_entity_text_url);
                q->out_i32(entity->start);
                q->out_i32(entity->length);
                q->out_std_string(entity->text_url);
                break;
            default:
                assert(0);
            }
        }
    }

    m_callback->new_messages({message});
    q->execute(active_client());
}

int64_t user_agent::send_text_message(const tgl_input_peer_t& peer_id,
        const std::string& text,
        int64_t message_id,
        int32_t reply_id,
        bool disable_preview,
        bool post_as_channel_message,
        bool send_as_secret_chat_service_message,
        const std::function<void(bool success, const std::shared_ptr<tgl_message>& message)>& callback)
{
    std::shared_ptr<secret_chat> sc;
    if (peer_id.peer_type == tgl_peer_type::enc_chat) {
        sc = secret_chat_for_id(peer_id);
        if (!sc) {
            TGL_ERROR("unknown secret chat");
            if (callback) {
                callback(false, nullptr);
            }
            return 0;
        }
        if (sc->state() != tgl_secret_chat_state::ok) {
            TGL_ERROR("secret chat not in ok state");
            if (callback) {
                callback(false, nullptr);
            }
            return 0;
        }
    }

    int64_t date = tgl_get_system_time();

    while (!message_id) {
        tgl_secure_random(reinterpret_cast<unsigned char*>(&message_id), 8);
    }

    if (peer_id.peer_type != tgl_peer_type::enc_chat) {
        tl_ds_message_media TDSM;
        TDSM.magic = CODE_message_media_empty;
        tgl_peer_id_t from_id;
        if (post_as_channel_message) {
            from_id = tgl_peer_id_t::from_input_peer(peer_id);
        } else {
            from_id = our_id();
        }
        auto m = std::make_shared<message>(message_id, from_id, peer_id, nullptr, nullptr, &date, text, &TDSM, nullptr, reply_id, nullptr);
        m->set_unread(true).set_outgoing(true).set_pending(true);
        send_text_message(m, disable_preview, callback);
    } else {
        assert(sc);
        if (send_as_secret_chat_service_message) {
            tl_ds_decrypted_message_action action;
            tl_ds_string opaque_message;
            memset(&action, 0, sizeof(action));
            opaque_message.data = const_cast<char*>(text.data());
            opaque_message.len = text.size();
            action.magic = CODE_decrypted_message_action_opaque_message;
            action.message = &opaque_message;
            sc->send_action(action, message_id, callback);
        } else {
            tl_ds_decrypted_message_media TDSM;
            TDSM.magic = CODE_decrypted_message_media_empty;
            tgl_peer_id_t from_id = our_id();
            auto m = std::make_shared<message>(sc, message_id, from_id, &date, text, &TDSM, nullptr, nullptr);
            m->set_unread(true).set_pending(true);
            sc->send_message(m, callback);
        }
    }

    return message_id;
}


void user_agent::mark_encrypted_message_read(const tgl_input_peer_t& id, int32_t max_time,
        const std::function<void(bool success)>& callback)
{
    if (id.peer_type != tgl_peer_type::enc_chat) {
        assert(false);
        return;
    }

    std::shared_ptr<secret_chat> sc = secret_chat_for_id(id);
    if (!sc) {
        TGL_ERROR("unknown secret chat");
        if (callback) {
            callback(false);
        }
        return;
    }
    sc->mark_messages_read(max_time, nullptr);
}

void user_agent::mark_message_read(const tgl_input_peer_t& id, int max_id_or_time,
        const std::function<void(bool)>& callback)
{
    if (id.peer_type == tgl_peer_type::enc_chat) {
        mark_encrypted_message_read(id, max_id_or_time, callback);
        return;
    }

    if (id.peer_type != tgl_peer_type::channel) {
        auto q = std::make_shared<query_mark_message_read>(id, max_id_or_time, callback);
        q->out_i32(CODE_messages_read_history);
        q->out_input_peer(this, id);
        q->out_i32(max_id_or_time);
        q->execute(active_client());
    } else {
        auto q = std::make_shared<query_mark_message_read>(id, max_id_or_time, callback);
        q->out_i32(CODE_channels_read_history);
        q->out_i32(CODE_input_channel);
        q->out_i32(id.peer_id);
        q->out_i64(id.access_hash);
        q->out_i32(max_id_or_time);
        q->execute(active_client());
    }
}

void user_agent::get_history(const tgl_input_peer_t& id, int offset, int limit,
        const std::function<void(bool, const std::vector<std::shared_ptr<tgl_message>>& list)>& callback) {
    assert(id.peer_type != tgl_peer_type::enc_chat);
    auto q = std::make_shared<query_get_history>(id, limit, offset, 0/*max_id*/, callback);
    q->out_i32(CODE_messages_get_history);
    q->out_input_peer(this, id);
    q->out_i32(0); // offset_id
    q->out_i32(offset); // add_offset
    q->out_i32(limit);
    q->out_i32(0); // max_id
    q->out_i32(0); // min_id
    q->execute(active_client());
}

void user_agent::get_dialog_list(int limit, int offset,
        const std::function<void(bool success,
                const std::vector<tgl_peer_id_t>& peers,
                const std::vector<int64_t>& last_msg_ids,
                const std::vector<int>& unread_count)>& callback)
{
    std::shared_ptr<get_dialogs_state> state = std::make_shared<get_dialogs_state>();
    state->limit = limit;
    state->offset = offset;
    state->channels = 0;
    state->weak_user_agent = std::weak_ptr<user_agent>(shared_from_this());
    tgl_do_get_dialog_list(state, callback);
}

void user_agent::get_channels_dialog_list(int limit, int offset,
        const std::function<void(bool success,
                const std::vector<tgl_peer_id_t>& peers,
                const std::vector<int64_t>& last_msg_ids,
                const std::vector<int>& unread_count)>& callback)
{
    std::shared_ptr<get_dialogs_state> state = std::make_shared<get_dialogs_state>();
    state->limit = limit;
    state->offset = offset;
    state->channels = 1;
    state->offset_date = 0;
    state->offset_peer.peer_type = tgl_peer_type::unknown;
    state->weak_user_agent = std::weak_ptr<user_agent>(shared_from_this());
    tgl_do_get_dialog_list(state, callback);
}

void user_agent::set_profile_name(const std::string& first_name, const std::string& last_name,
        const std::function<void(bool)>& callback)
{
    auto q = std::make_shared<query_set_profile_name>(callback);
    q->out_i32(CODE_account_update_profile);
    q->out_std_string(first_name);
    q->out_std_string(last_name);
    q->execute(active_client());
}

void user_agent::set_username(const std::string& username, const std::function<void(bool success)>& callback)
{
    auto q = std::make_shared<query_set_profile_name>(callback);
    q->out_i32(CODE_account_update_username);
    q->out_std_string(username);
    q->execute(active_client());
}

void user_agent::check_username(const std::string& username, const std::function<void(int result)>& callback)
{
    auto q = std::make_shared<query_check_username>(callback);
    q->out_i32(CODE_account_check_username);
    q->out_std_string(username);
    q->execute(active_client());
}

void user_agent::search_contact(const std::string& name, int limit,
        const std::function<void(const std::vector<std::shared_ptr<tgl_user>>&,
                           const std::vector<std::shared_ptr<tgl_chat>>&)>& callback)
{
    auto q = std::make_shared<query_search_contact>(callback);
    q->out_i32(CODE_contacts_search);
    q->out_std_string(name);
    q->out_i32(limit);
    q->execute(active_client());
}

void user_agent::resolve_username(const std::string& name, const std::function<void(bool success)>& callback)
{
    auto q = std::make_shared<query_resolve_username>(callback);
    q->out_i32(CODE_contacts_resolve_username);
    q->out_std_string(name);
    q->execute(active_client());
}

void user_agent::forward_messages(const tgl_input_peer_t& from_id, const tgl_input_peer_t& to_id,
        const std::vector<int64_t>& message_ids, bool post_as_channel_message,
        const std::function<void(bool success, const std::vector<std::shared_ptr<tgl_message>>& messages)>& callback)
{
    if (to_id.peer_type == tgl_peer_type::enc_chat) {
        TGL_ERROR("can not forward messages to secret chats");
        if (callback) {
            callback(false, std::vector<std::shared_ptr<tgl_message>>());
        }
        return;
    }

    std::shared_ptr<messages_send_extra> E = std::make_shared<messages_send_extra>();
    E->multi = true;
    E->count = message_ids.size();

    auto q = std::make_shared<query_send_messages>(E, callback);
    q->out_i32(CODE_messages_forward_messages);

    unsigned f = 0;
    if (post_as_channel_message) {
        f |= 16;
    }
    q->out_i32(f);
    q->out_input_peer(this, from_id);
    q->out_i32(CODE_vector);
    q->out_i32(message_ids.size());
    for (size_t i = 0; i < message_ids.size(); i++) {
        q->out_i32(message_ids[i]);
    }

    q->out_i32(CODE_vector);
    q->out_i32(message_ids.size());
    for (size_t i = 0; i < message_ids.size(); i++) {
        int64_t new_message_id;
        tgl_secure_random(reinterpret_cast<unsigned char*>(&new_message_id), 8);
        E->message_ids.push_back(new_message_id);
        q->out_i64(new_message_id);
    }
    q->out_input_peer(this, to_id);
    q->execute(active_client());
}

void user_agent::forward_message(const tgl_input_peer_t& from_id, const tgl_input_peer_t& to_id, int64_t message_id,
        const std::function<void(bool success, const std::shared_ptr<tgl_message>& message)>& callback)
{
    if (from_id.peer_type == tgl_peer_type::temp_id) {
        TGL_ERROR("unknown message");
        if (callback) {
            callback(false, nullptr);
        }
        return;
    }
    if (from_id.peer_type == tgl_peer_type::enc_chat) {
        TGL_ERROR("can not forward messages from secret chat");
        if (callback) {
            callback(false, nullptr);
        }
        return;
    }
    if (to_id.peer_type == tgl_peer_type::enc_chat) {
        TGL_ERROR("can not forward messages to secret chats");
        if (callback) {
            callback(false, nullptr);
        }
        return;
    }

    std::shared_ptr<messages_send_extra> E = std::make_shared<messages_send_extra>();
    tgl_secure_random(reinterpret_cast<unsigned char*>(&E->id), 8);
    auto q = std::make_shared<query_send_messages>(E, callback);
    q->out_i32(CODE_messages_forward_message);
    q->out_input_peer(this, from_id);
    q->out_i32(message_id);

    q->out_i64(E->id);
    q->out_input_peer(this, to_id);
    q->execute(active_client());
}

void user_agent::send_contact(const tgl_input_peer_t& id,
      const std::string& phone, const std::string& first_name, const std::string& last_name, int32_t reply_id,
      const std::function<void(bool success, const std::shared_ptr<tgl_message>& message)>& callback)
{
    if (id.peer_type == tgl_peer_type::enc_chat) {
        TGL_ERROR("can not send contact to secret chat");
        if (callback) {
            callback(false, nullptr);
        }
        return;
    }

    std::shared_ptr<messages_send_extra> E = std::make_shared<messages_send_extra>();
    tgl_secure_random(reinterpret_cast<unsigned char*>(&E->id), 8);

    auto q = std::make_shared<query_send_messages>(E, callback);
    q->out_i32(CODE_messages_send_media);
    q->out_i32(reply_id ? 1 : 0);
    if (reply_id) {
        q->out_i32(reply_id);
    }
    q->out_input_peer(this, id);
    q->out_i32(CODE_input_media_contact);
    q->out_std_string(phone);
    q->out_std_string(first_name);
    q->out_std_string(last_name);

    q->out_i64(E->id);

    q->execute(active_client());
}

//void tgl_do_reply_contact(tgl_message_id_t *_reply_id, const std::string& phone, const std::string& first_name, const std::string& last_name,
//        unsigned long long flags, std::function<void(bool success, const std::shared_ptr<tgl_message>& M, float progress)> callback)
//{
//  tgl_message_id_t reply_id = *_reply_id;
//  if (reply_id.peer_type == tgl_peer_type::temp_id) {
//    TGL_ERROR("unknown message");
//    if (callback) {
//      callback(0, 0, 0);
//    }
//    return;
//  }
//  if (reply_id.peer_type == tgl_peer_type::enc_chat) {
//    TGL_ERROR("can not reply on message from secret chat");
//    if (callback) {
//      callback(0, 0, 0);
//    }

//    tgl_peer_id_t peer_id = tgl_msg_id_to_peer_id(reply_id);

//    tgl_do_send_contact(peer_id, phone, first_name, last_name, flags | TGL_SEND_MSG_FLAG_REPLY(reply_id.id), callback);
//  }
//}

void user_agent::forward_media(const tgl_input_peer_t& to_id, int64_t message_id, bool post_as_channel_message,
        const std::function<void(bool success, const std::shared_ptr<tgl_message>& message)>& callback)
{
    if (to_id.peer_type == tgl_peer_type::enc_chat) {
        TGL_ERROR("can not forward messages to secret chats");
        if (callback) {
            callback(false, nullptr);
        }
        return;
    }
#if 0
    struct tgl_message* M = tgl_message_get(&msg_id);
    if (!M || !(M->flags & TGLMF_CREATED) || (M->flags & TGLMF_ENCRYPTED)) {
        if (!M || !(M->flags & TGLMF_CREATED)) {
            TGL_ERROR("unknown message");
        } else {
            TGL_ERROR("can not forward message from secret chat");
        }
        if (callback) {
            callback(false, nullptr);
        }
        return;
    }
    if (M->media.type != tgl_message_media_photo && M->media.type != tgl_message_media_document && M->media.type != tgl_message_media_audio && M->media.type != tgl_message_media_video) {
        TGL_ERROR("can only forward photo/document");
        if (callback) {
            callback(false, nullptr);
        }
        return;
    }
#endif
    std::shared_ptr<messages_send_extra> E = std::make_shared<messages_send_extra>();
    tgl_secure_random(reinterpret_cast<unsigned char*>(&E->id), 8);

    auto q = std::make_shared<query_send_messages>(E, callback);
    q->out_i32(CODE_messages_send_media);
    int f = 0;
    if (post_as_channel_message) {
        f |= 16;
    }
    q->out_i32(f);
    q->out_input_peer(this, to_id);
#if 0
    switch (M->media.type) {
    case tgl_message_media_photo:
        assert(M->media.photo);
        out_i32(CODE_input_media_photo);
        out_i32(CODE_input_photo);
        out_i64(M->media.photo->id);
        out_i64(M->media.photo->access_hash);
        out_string("");
        break;
    case tgl_message_media_document:
    case tgl_message_media_audio:
    case tgl_message_media_video:
        assert(M->media.document);
        out_i32(CODE_input_media_document);
        out_i32(CODE_input_document);
        out_i64(M->media.document->id);
        out_i64(M->media.document->access_hash);
        out_string("");
        break;
    default:
       assert(0);
    }
#endif

  q->out_i64(E->id);
  q->execute(active_client());
}

void user_agent::send_location(const tgl_input_peer_t& peer_id, double latitude, double longitude, int32_t reply_id, bool post_as_channel_message,
        const std::function<void(bool success, const std::shared_ptr<tgl_message>& message)>& callback)
{
    if (peer_id.peer_type == tgl_peer_type::enc_chat) {
        auto sc = secret_chat_for_id(peer_id);
        if (sc) {
            sc->send_location(latitude, longitude, callback);
        } else {
            if (callback) {
                callback(false, nullptr);
            }
        }
    } else {
        std::shared_ptr<messages_send_extra> E = std::make_shared<messages_send_extra>();
        tgl_secure_random(reinterpret_cast<unsigned char*>(&E->id), 8);

        auto q = std::make_shared<query_send_messages>(E, callback);
        q->out_i32(CODE_messages_send_media);
        unsigned f = reply_id ? 1 : 0;
        if (post_as_channel_message) {
            f |= 16;
        }
        q->out_i32(f);
        if (reply_id) {
            q->out_i32(reply_id);
        }
        q->out_input_peer(this, peer_id);
        q->out_i32(CODE_input_media_geo_point);
        q->out_i32(CODE_input_geo_point);
        q->out_double(latitude);
        q->out_double(longitude);

        q->out_i64(E->id);

        q->execute(active_client());
    }
}

#if 0
void tgl_do_reply_location(tgl_message_id_t *_reply_id, double latitude, double longitude, unsigned long long flags, std::function<void(bool success, struct tgl_message* M)> callback) {
  tgl_message_id_t reply_id = *_reply_id;
  if (reply_id.peer_type == tgl_peer_type::temp_id) {
    reply_id = tgl_convert_temp_msg_id(reply_id);
  }
  if (reply_id.peer_type == tgl_peer_type::temp_id) {
    TGL_ERROR("unknown message");
    if (callback) {
      callback(0, 0);
    }
    return;
  }
  if (reply_id.peer_type == tgl_peer_type::enc_chat) {
    TGL_ERROR("can not reply on message from secret chat");
    if (callback) {
      callback(0, 0);
    }

  tgl_peer_id_t peer_id = tgl_msg_id_to_peer_id(reply_id);

  tgl_do_send_location(peer_id, latitude, longitude, flags | TGL_SEND_MSG_FLAG_REPLY(reply_id.id), callback, callback_extra);
}
#endif

void user_agent::rename_chat(const tgl_input_peer_t& id, const std::string& new_title,
                        const std::function<void(bool success)>& callback)
{
    auto q = std::make_shared<query_send_messages>(callback);
    q->out_i32(CODE_messages_edit_chat_title);
    assert(id.peer_type == tgl_peer_type::chat);
    q->out_i32(id.peer_id);
    q->out_std_string(new_title);
    q->execute(active_client());
}

void user_agent::rename_channel(const tgl_input_peer_t& id, const std::string& name,
        const std::function<void(bool success)>& callback)
{
    auto q = std::make_shared<query_send_messages>(callback);
    q->out_i32(CODE_channels_edit_title);
    assert(id.peer_type == tgl_peer_type::channel);
    q->out_i32(CODE_input_channel);
    q->out_i32(id.peer_id);
    q->out_i64(id.access_hash);
    q->out_std_string(name);
    q->execute(active_client());
}

void user_agent::join_channel(const tgl_input_peer_t& id, const std::function<void(bool success)>& callback)
{
    auto q = std::make_shared<query_send_messages>(callback);
    q->out_i32(CODE_channels_join_channel);
    assert(id.peer_type == tgl_peer_type::channel);
    q->out_i32(CODE_input_channel);
    q->out_i32(id.peer_id);
    q->out_i64(id.access_hash);
    q->execute(active_client());
}

void user_agent::leave_channel(const tgl_input_peer_t& id, const std::function<void(bool success)>& callback)
{
    auto q = std::make_shared<query_send_messages>(callback);
    q->out_i32(CODE_channels_leave_channel);
    assert(id.peer_type == tgl_peer_type::channel);
    q->out_i32(CODE_input_channel);
    q->out_i32(id.peer_id);
    q->out_i64(id.access_hash);
    q->execute(active_client());
}

void user_agent::delete_channel(const tgl_input_peer_t& channel_id, const std::function<void(bool success)>& callback)
{
    std::shared_ptr<messages_send_extra> extra = std::make_shared<messages_send_extra>();
    extra->multi = true;
    auto q = std::make_shared<query_send_messages>(extra, [=](bool success, const std::vector<std::shared_ptr<tgl_message>>&) {
        if (callback) {
            callback(success);
        }
    });
    q->out_i32(CODE_channels_delete_channel);
    assert(channel_id.peer_type == tgl_peer_type::channel);
    q->out_i32(CODE_input_channel);
    q->out_i32(channel_id.peer_id);
    q->out_i64(channel_id.access_hash);
    q->execute(active_client());
}

void user_agent::channel_edit_title(const tgl_input_peer_t& channel_id,
        const std::string& title,
        const std::function<void(bool success)>& callback)
{
     auto q = std::make_shared<query_send_messages>(callback);
     q->out_i32(CODE_channels_edit_title);
     assert(channel_id.peer_type == tgl_peer_type::channel);
     q->out_i32(CODE_input_channel);
     q->out_i32(channel_id.peer_id);
     q->out_i64(channel_id.access_hash);
     q->out_std_string(title);
     q->execute(active_client());
}

void user_agent::channel_set_about(const tgl_input_peer_t& id, const std::string& about,
        const std::function<void(bool success)>& callback)
{
    auto q = std::make_shared<query_channels_set_about>(callback);
    q->out_i32(CODE_channels_edit_about);
    assert(id.peer_type == tgl_peer_type::channel);
    q->out_i32(CODE_input_channel);
    q->out_i32(id.peer_id);
    q->out_i64(id.access_hash);
    q->out_std_string(about);
    q->execute(active_client());
}

void user_agent::channel_set_username(const tgl_input_peer_t& id, const std::string& username,
        const std::function<void(bool success)>& callback)
{
    auto q = std::make_shared<query_channels_set_about>(callback);
    q->out_i32(CODE_channels_update_username);
    assert(id.peer_type == tgl_peer_type::channel);
    q->out_i32(CODE_input_channel);
    q->out_i32(id.peer_id);
    q->out_i64(id.access_hash);
    q->out_std_string(username);
    q->execute(active_client());
}

void user_agent::channel_set_admin(const tgl_input_peer_t& channel_id, const tgl_input_peer_t& user_id, int type,
        const std::function<void(bool success)>& callback)
{
    auto q = std::make_shared<query_send_messages>(callback);
    q->out_i32(CODE_channels_edit_admin);
    assert(channel_id.peer_type == tgl_peer_type::channel);
    assert(user_id.peer_type == tgl_peer_type::user);
    q->out_i32(CODE_input_channel);
    q->out_i32(channel_id.peer_id);
    q->out_i64(channel_id.access_hash);
    q->out_i32(CODE_input_user);
    q->out_i32(user_id.peer_id);
    q->out_i64(user_id.access_hash);
    switch (type) {
    case 1:
        q->out_i32(CODE_channel_role_moderator);
        break;
    case 2:
        q->out_i32(CODE_channel_role_editor);
        break;
    default:
        q->out_i32(CODE_channel_role_empty);
        break;
    }

    q->execute(active_client());
}

void user_agent::get_channel_participants(const tgl_input_peer_t& channel_id, int limit, int offset, tgl_channel_participant_type type,
        const std::function<void(bool success)>& callback)
{
    std::shared_ptr<channel_get_participants_state> state = std::make_shared<channel_get_participants_state>();
    state->type = type;
    state->channel_id = channel_id;
    state->limit = limit;
    state->offset = offset;
    state->weak_user_agent = std::weak_ptr<user_agent>(shared_from_this());
    tgl_do_get_channel_participants(state, callback);
}

void user_agent::get_channel_participant_self(const tgl_input_peer_t& channel_id, const std::function<void(bool success)>& callback)
{
    auto q = std::make_shared<query_channel_get_participant>(channel_id.peer_id, callback);
    q->out_i32(CODE_channels_get_participant);
    q->out_i32(CODE_input_channel);
    q->out_i32(channel_id.peer_id);
    q->out_i64(channel_id.access_hash);
    q->out_i32(CODE_input_user_self);
    q->execute(active_client());
}

void user_agent::get_chat_info(int32_t id, const std::function<void(bool success)>& callback)
{
    auto q = std::make_shared<query_get_chat_info>(callback);
    q->out_i32(CODE_messages_get_full_chat);
    q->out_i32(id);
    q->execute(active_client());
}

void user_agent::get_channel_info(const tgl_input_peer_t& id,
        const std::function<void(bool success)>& callback)
{
    auto q = std::make_shared<query_get_channel_info>(callback);
    q->out_i32(CODE_channels_get_full_channel);
    assert(id.peer_type == tgl_peer_type::channel);
    q->out_i32(CODE_input_channel);
    q->out_i32(id.peer_id);
    q->out_i64(id.access_hash);
    q->execute(active_client());
}

void user_agent::get_user_info(const tgl_input_peer_t& id, const std::function<void(bool success, const std::shared_ptr<tgl_user>& user)>& callback)
{
    if (id.peer_type != tgl_peer_type::user) {
        TGL_ERROR("id should be user id");
        if (callback) {
            callback(false, nullptr);
        }
        return;
    }

    auto q = std::make_shared<query_user_info>(callback);
    q->out_i32(CODE_users_get_full_user);
    assert(id.peer_type == tgl_peer_type::user);
    q->out_i32(CODE_input_user);
    q->out_i32(id.peer_id);
    q->out_i64(id.access_hash);
    q->execute(active_client());
}

void user_agent::add_contacts(const std::vector<std::tuple<std::string, std::string, std::string>>& contacts, bool replace,
        const std::function<void(bool success, const std::vector<int32_t>& user_ids)>& callback)
{
    auto q = std::make_shared<query_add_contacts>(callback);
    q->out_i32(CODE_contacts_import_contacts);
    q->out_i32(CODE_vector);
    q->out_i32(contacts.size());
    int64_t r;

    for (const auto& contact : contacts) {
        const auto& phone = std::get<0>(contact);
        const auto& first_name = std::get<1>(contact);
        const auto& last_name = std::get<2>(contact);

        q->out_i32(CODE_input_phone_contact);
        tgl_secure_random(reinterpret_cast<unsigned char*>(&r), 8);
        q->out_i64(r);
        q->out_std_string(phone);
        q->out_std_string(first_name);
        q->out_std_string(last_name);
    }

    q->out_i32(replace ? CODE_bool_true : CODE_bool_false);
    q->execute(active_client());
}

void user_agent::delete_contact(const tgl_input_peer_t& id, const std::function<void(bool success)>& callback)
{
    if (id.peer_type != tgl_peer_type::user) {
        TGL_ERROR("the peer id user be user id");
        if (callback) {
            callback(false);
        }
        return;
    }

    std::weak_ptr<user_agent> weak_ua = shared_from_this();
    int32_t user_id = id.peer_id;
    auto q = std::make_shared<query_delete_contact>([=](bool success) {
        if (success) {
            if (auto ua = weak_ua.lock()) {
                ua->callback()->user_deleted(user_id);
            }
        }
        if (callback) {
            callback(success);
        }
    });
    q->out_i32(CODE_contacts_delete_contact);
    q->out_i32(CODE_input_user);
    q->out_i32(id.peer_id);
    q->out_i64(id.access_hash);
    q->execute(active_client());
}

void user_agent::search_message(const tgl_input_peer_t& id, int from, int to, int limit, int offset, const std::string &query,
        const std::function<void(bool success, const std::vector<std::shared_ptr<tgl_message>>& list)>& callback) {
    if (id.peer_type == tgl_peer_type::enc_chat) {
        TGL_ERROR("can not search in secret chats");
        if (callback) {
            callback(false, std::vector<std::shared_ptr<tgl_message>>());
        }
        return;
    }
    std::shared_ptr<msg_search_state> state = std::make_shared<msg_search_state>(id, from, to, limit, offset, query);
    state->weak_user_agent = std::weak_ptr<user_agent>(shared_from_this());
    tgl_do_msg_search(state, callback);
}

void user_agent::lookup_state()
{
    if (is_diff_locked()) {
        return;
    }
    auto q = std::make_shared<query_lookup_state>(nullptr);
    q->out_header(this);
    q->out_i32(CODE_updates_get_state);
    q->execute(active_client());
}

void user_agent::get_difference(bool sync_from_start, const std::function<void(bool success)>& callback)
{
    if (is_diff_locked()) {
        if (callback) {
            callback(false);
        }
        return;
    }
    set_diff_locked(true);
    if (pts() > 0 || sync_from_start) {
        if (pts() == 0) {
            set_pts(1, true);
        }
        if (date() == 0) {
            set_date(1, true);
        }
        auto q = std::make_shared<query_get_difference>(callback);
        q->out_header(this);
        q->out_i32(CODE_updates_get_difference);
        q->out_i32(pts());
        q->out_i32(date());
        q->out_i32(qts());
        q->execute(active_client());
    } else {
        auto q = std::make_shared<query_get_state>(callback);
        q->out_header(this);
        q->out_i32(CODE_updates_get_state);
        q->execute(active_client());
    }
}

void user_agent::get_channel_difference(const tgl_input_peer_t& channel_id,
        const std::function<void(bool success)>& callback)
{
    std::shared_ptr<channel> c = channel::create_bare(channel_id);

    // FIXME: apparently this function doesn't work. We need to at least pass channel pts in.
    if (!c->pts()) {
        if (callback) {
            callback(false);
        }
        return;
    }

    if (c->is_diff_locked()) {
        TGL_WARNING("channel " << c->id().peer_id << " diff locked");
        if (callback) {
            callback(false);
        }
        return;
    }
    c->set_diff_locked(true);

    auto q = std::make_shared<query_get_channel_difference>(c, callback);
    q->out_header(this);
    q->out_i32(CODE_updates_get_channel_difference);
    q->out_i32(CODE_input_channel);
    q->out_i32(c->id().peer_id);
    q->out_i64(c->id().access_hash);
    q->out_i32(CODE_channel_messages_filter_empty);
    q->out_i32(c->pts());
    q->out_i32(100);
    q->execute(active_client());
}

void user_agent::add_user_to_chat(const tgl_peer_id_t& chat_id, const tgl_input_peer_t& user_id, int32_t limit,
        const std::function<void(bool success)>& callback) {
    auto q = std::make_shared<query_send_messages>(callback);
    q->out_i32(CODE_messages_add_chat_user);
    q->out_i32(chat_id.peer_id);

    assert(user_id.peer_type == tgl_peer_type::user);
    q->out_i32(CODE_input_user);
    q->out_i32(user_id.peer_id);
    q->out_i64(user_id.access_hash);
    q->out_i32(limit);

    q->execute(active_client());
}

void user_agent::delete_user_from_chat(int32_t chat_id, const tgl_input_peer_t& user_id,
        const std::function<void(bool success)>& callback)
{
    auto q = std::make_shared<query_send_messages>(callback);
    q->out_i32(CODE_messages_delete_chat_user);
    q->out_i32(chat_id);

    assert(user_id.peer_type == tgl_peer_type::user);
    if (user_id.peer_id == our_id().peer_id) {
        q->out_i32(CODE_input_user_self);
    } else {
        q->out_i32(CODE_input_user);
        q->out_i32(user_id.peer_id);
        q->out_i64(user_id.access_hash);
    }

    q->execute(active_client());
}

void user_agent::channel_invite_user(const tgl_input_peer_t& channel_id, const std::vector<tgl_input_peer_t>& user_ids,
        const std::function<void(bool success)>& callback)
{
    if (user_ids.empty()) {
        if (callback) {
            callback(true);
        }
        return;
    }

    auto q = std::make_shared<query_send_messages>(callback);
    q->out_i32(CODE_channels_invite_to_channel);
    q->out_i32(CODE_input_channel);
    q->out_i32(channel_id.peer_id);
    q->out_i64(channel_id.access_hash);

    q->out_i32(CODE_vector);
    q->out_i32(user_ids.size());
    for (const auto& user_id: user_ids) {
        assert(user_id.peer_type == tgl_peer_type::user);
        q->out_i32(CODE_input_user);
        q->out_i32(user_id.peer_id);
        q->out_i64(user_id.access_hash);
    }

    q->execute(active_client());
}

void user_agent::channel_delete_user(const tgl_input_peer_t& channel_id, const tgl_input_peer_t& user_id,
    const std::function<void(bool success)>& callback)
{
    auto q = std::make_shared<query_send_messages>(callback);
    q->out_i32(CODE_channels_kick_from_channel);
    q->out_i32(CODE_input_channel);
    q->out_i32(channel_id.peer_id);
    q->out_i64(channel_id.access_hash);

    q->out_i32(CODE_input_user);
    q->out_i32(user_id.peer_id);
    q->out_i64(user_id.access_hash);

    q->out_i32(CODE_bool_true);

    q->execute(active_client());
}

void user_agent::create_group_chat(const std::vector<tgl_input_peer_t>& user_ids, const std::string& chat_topic,
        const std::function<void(int32_t chat_id)>& callback)
{
    auto q = std::make_shared<query_create_chat>(callback);
    q->out_i32(CODE_messages_create_chat);
    q->out_i32(CODE_vector);
    q->out_i32(user_ids.size()); // Number of users, currently we support only 1 user.
    for (auto id : user_ids) {
        if (id.peer_type != tgl_peer_type::user) {
            TGL_ERROR("can not create chat with unknown user");
            if (callback) {
                callback(false);
            }
            return;
        }
        q->out_i32(CODE_input_user);
        q->out_i32(id.peer_id);
        q->out_i64(id.access_hash);
        TGL_DEBUG("adding user - peer_id: " << id.peer_id << ", access_hash: " << id.access_hash);
    }
    TGL_DEBUG("sending out chat creat request users number: " << user_ids.size() << ", chat_topic: " << chat_topic);
    q->out_std_string(chat_topic);
    q->execute(active_client());
}

void user_agent::create_channel(const std::string& topic, const std::string& about,
        bool broadcast, bool mega_group,
        const std::function<void(int32_t channel_id)>& callback)
{
    int32_t flags = 0;
    if (broadcast) {
        flags |= 1;
    }
    if (mega_group) {
        flags |= 2;
    }
    auto q = std::make_shared<query_create_chat>(callback, true);
    q->out_i32(CODE_channels_create_channel);
    q->out_i32(flags);
    q->out_std_string(topic);
    q->out_std_string(about);

    q->execute(active_client());
}

void user_agent::delete_message(const tgl_input_peer_t& chat, int64_t message_id,
        const std::function<void(bool success)>& callback)
{
    if (chat.peer_type == tgl_peer_type::enc_chat) {
        auto sc = secret_chat_for_id(chat.peer_id);
        if (!sc) {
            TGL_ERROR("could not find secret chat");
            if (callback) {
                callback(false);
            }
            return;
        }
        sc->delete_message(message_id, nullptr);
        return;
    }

    if (chat.peer_type == tgl_peer_type::temp_id) {
        TGL_ERROR("unknown message");
        if (callback) {
            callback(false);
        }
        return;
    }
    auto q = std::make_shared<query_delete_message>(chat, message_id, callback);
    if (chat.peer_type == tgl_peer_type::channel) {
        q->out_i32(CODE_channels_delete_messages);
        q->out_i32(CODE_input_channel);
        q->out_i32(chat.peer_id);
        q->out_i64(chat.access_hash);

        q->out_i32(CODE_vector);
        q->out_i32(1);
        q->out_i32(message_id);
    } else {
        q->out_i32(CODE_messages_delete_messages);
        q->out_i32(CODE_vector);
        q->out_i32(1);
        q->out_i32(message_id);
    }

    q->execute(active_client());
}

void user_agent::export_card(const std::function<void(bool success, const std::vector<int>& card)>& callback)
{
    auto q = std::make_shared<query_export_card>(callback);
    q->out_i32(CODE_contacts_export_card);
    q->execute(active_client());
}

void user_agent::import_card(int size, int* card,
        const std::function<void(bool success, const std::shared_ptr<tgl_user>& user)>& callback)
{
    auto q = std::make_shared<query_import_card>(callback);
    q->out_i32(CODE_contacts_import_card);
    q->out_i32(CODE_vector);
    q->out_i32(size);
    q->out_i32s(card, size);
    q->execute(active_client());
}

void user_agent::start_bot(const tgl_input_peer_t& bot, const tgl_peer_id_t& chat,
        const std::string& name, const std::function<void(bool success)>& callback)
{
    auto q = std::make_shared<query_send_messages>(callback);
    q->out_i32(CODE_messages_start_bot);
    q->out_i32(CODE_input_user);
    q->out_i32(bot.peer_id);
    q->out_i64(bot.access_hash);
    q->out_i32(chat.peer_id);
    int64_t m = 0;
    while (!m) {
        tgl_secure_random(reinterpret_cast<unsigned char*>(&m), 8);
    }
    q->out_i64(m);
    q->out_std_string(name);

    q->execute(active_client());
}

void user_agent::send_typing(const tgl_input_peer_t& id, tgl_typing_status status,
        const std::function<void(bool success)>& callback)
{
    if (id.peer_type != tgl_peer_type::enc_chat) {
        auto q = std::make_shared<query_send_typing>(callback);
        q->out_i32(CODE_messages_set_typing);
        q->out_input_peer(this, id);
        switch (status) {
        case tgl_typing_status::none:
        case tgl_typing_status::typing:
            q->out_i32(CODE_send_message_typing_action);
            break;
        case tgl_typing_status::cancel:
            q->out_i32(CODE_send_message_cancel_action);
            break;
        case tgl_typing_status::record_video:
            q->out_i32(CODE_send_message_record_video_action);
            break;
        case tgl_typing_status::upload_video:
            q->out_i32(CODE_send_message_upload_video_action);
            q->out_i32(0);
            break;
        case tgl_typing_status::record_audio:
            q->out_i32(CODE_send_message_record_audio_action);
            break;
        case tgl_typing_status::upload_audio:
            q->out_i32(CODE_send_message_upload_audio_action);
            q->out_i32(0);
            break;
        case tgl_typing_status::upload_photo:
            q->out_i32(CODE_send_message_upload_photo_action);
            q->out_i32(0);
            break;
        case tgl_typing_status::upload_document:
            q->out_i32(CODE_send_message_upload_document_action);
            q->out_i32(0);
            break;
        case tgl_typing_status::geo:
            q->out_i32(CODE_send_message_geo_location_action);
            break;
        case tgl_typing_status::choose_contact:
            q->out_i32(CODE_send_message_choose_contact_action);
            break;
        }
        q->execute(active_client());
    } else {
        if (callback) {
            callback(false);
        }
    }
}

void user_agent::get_message(int64_t message_id,
        const std::function<void(bool success, const std::shared_ptr<tgl_message>&)>& callback)
{
    auto q = std::make_shared<query_get_messages>(callback);
    q->out_i32(CODE_messages_get_messages);
    q->out_i32(CODE_vector);
    q->out_i32(1);
    q->out_i32(message_id);
    q->execute(active_client());
}

void user_agent::export_chat_link(const tgl_peer_id_t& id, const std::function<void(bool success, const std::string& link)>& callback)
{
    if (id.peer_type != tgl_peer_type::chat) {
        TGL_ERROR("Can only export chat link for chat");
        if (callback) {
            callback(false, std::string());
        }
        return;
    }

    auto q = std::make_shared<query_export_chat_link>(callback);
    q->out_i32(CODE_messages_export_chat_invite);
    q->out_i32(id.peer_id);

    q->execute(active_client());
}

void user_agent::import_chat_link(const std::string& link,
        const std::function<void(bool success)>& callback)
{
    const char* link_str = link.c_str();
    const char* l = link_str + link.size() - 1;
    while (l >= link_str && *l != '/') {
        l--;
    }
    l++;

    auto q = std::make_shared<query_send_messages>(callback);
    q->out_i32(CODE_messages_import_chat_invite);
    q->out_string(l, link.size() - (l - link_str));

    q->execute(active_client());
}

void user_agent::export_channel_link(const tgl_input_peer_t& id,
        const std::function<void(bool success, const std::string& link)>& callback)
{
    if (id.peer_type != tgl_peer_type::channel) {
        TGL_ERROR("can only export chat link for chat");
        if (callback) {
            callback(false, std::string());
        }
        return;
    }

    auto q = std::make_shared<query_export_chat_link>(callback);
    q->out_i32(CODE_channels_export_invite);
    q->out_i32(CODE_input_channel);
    q->out_i32(id.peer_id);
    q->out_i64(id.access_hash);
    q->execute(active_client());
}

void user_agent::update_password_settings(const std::function<void(bool success)>& callback)
{
    auto q = std::make_shared<query_get_and_set_password>(callback);
    q->out_i32(CODE_account_get_password);
    q->execute(active_client());
}

void user_agent::password_got(const std::string& current_salt, const std::string& password,
        const std::function<void(bool)>& callback)
{
    char s[512];
    unsigned char shab[32];
    memset(s, 0, sizeof(s));
    memset(shab, 0, sizeof(shab));

    const char* pwd = password.data();
    size_t pwd_len = password.size();
    if (current_salt.size() > 128 || pwd_len > 128) {
        if (callback) {
            callback(false);
        }
        return;
    }

    auto q = std::make_shared<query_check_password>(callback);
    q->out_i32(CODE_auth_check_password);

    if (pwd && pwd_len && current_salt.size()) {
        memcpy(s, current_salt.data(), current_salt.size());
        memcpy(s + current_salt.size(), pwd, pwd_len);
        memcpy(s + current_salt.size() + pwd_len, current_salt.data(), current_salt.size());
        TGLC_sha256((const unsigned char *)s, 2 * current_salt.size() + pwd_len, shab);
        q->out_string((const char *)shab, 32);
    } else {
        q->out_string("");
    }

    q->execute(active_client(), query::execution_option::LOGIN);
}

void user_agent::check_password(const std::function<void(bool success)>& callback)
{
    std::weak_ptr<user_agent> weak_ua = shared_from_this();
    auto q = std::make_shared<query_get_and_check_password>([weak_ua, callback](const tl_ds_account_password* DS_AP) {
        auto ua = weak_ua.lock();
        if (!ua || !DS_AP) {
            if (ua) {
                ua->set_password_locked(false);
            }
            if (callback) {
                callback(false);
            }
            return;
        }

        if (DS_AP->magic == CODE_account_no_password) {
            ua->set_password_locked(false);
            return;
        }

        std::string current_salt = DS_STDSTR(DS_AP->current_salt);
        ua->callback()->get_value(std::make_shared<tgl_value_current_password>(
            [weak_ua, current_salt, callback](const std::string& password) {
                if (auto ua = weak_ua.lock()) {
                    ua->password_got(current_salt, password, callback);
                } else if (callback) {
                    callback(false);
                }
            }));
    });

    q->out_i32(CODE_account_get_password);
    q->execute(active_client(), query::execution_option::LOGIN);
}

void user_agent::send_broadcast(const std::vector<tgl_input_peer_t>& peers, const std::string& text,
        const std::function<void(bool success, const std::vector<std::shared_ptr<tgl_message>>& messages)>& callback)
{
    if (peers.size() > 1000) {
        if (callback) {
            callback(false, std::vector<std::shared_ptr<tgl_message>>());
        }
        return;
    }

    std::shared_ptr<messages_send_extra> E = std::make_shared<messages_send_extra>();
    E->multi = true;
    E->count = peers.size();

    for (size_t i = 0; i < peers.size(); i++) {
        assert(peers[i].peer_type == tgl_peer_type::user);

        int64_t message_id;
        tgl_secure_random(reinterpret_cast<unsigned char*>(&message_id), 8);
        E->message_ids.push_back(message_id);

        int64_t date = tgl_get_system_time();
        struct tl_ds_message_media TDSM;
        TDSM.magic = CODE_message_media_empty;

        auto m = std::make_shared<message>(message_id, our_id(), peers[i], nullptr, nullptr, &date, text, &TDSM, nullptr, 0, nullptr);
        m->set_unread(true).set_outgoing(true).set_pending(true);
        m_callback->new_messages({m});
    }

    auto q = std::make_shared<query_send_messages>(E, callback);
    q->out_i32(CODE_messages_send_broadcast);
    q->out_i32(CODE_vector);
    q->out_i32(peers.size());
    for (size_t i = 0; i < peers.size(); i++) {
        assert(peers[i].peer_type == tgl_peer_type::user);

        q->out_i32(CODE_input_user);
        q->out_i32(peers[i].peer_id);
        q->out_i64(peers[i].access_hash);
    }

    q->out_i32(CODE_vector);
    q->out_i32(peers.size());
    for (size_t i = 0; i < peers.size(); i++) {
        q->out_i64(E->message_ids[i]);
    }
    q->out_std_string(text);

    q->out_i32(CODE_message_media_empty);

    q->execute(active_client());
}

void user_agent::block_user(const tgl_input_peer_t& id, const std::function<void(bool success)>& callback)
{
    if (id.peer_type != tgl_peer_type::user) {
        TGL_ERROR("id should be user id");
        if (callback) {
            callback(false);
        }
        return;
    }

    auto q = std::make_shared<query_block_or_unblock_user>(callback);
    q->out_i32(CODE_contacts_block);
    q->out_i32(CODE_input_user);
    q->out_i32(id.peer_id);
    q->out_i64(id.access_hash);
    q->execute(active_client());
}

void user_agent::unblock_user(const tgl_input_peer_t& id, const std::function<void(bool success)>& callback)
{
    if (id.peer_type != tgl_peer_type::user) {
        TGL_ERROR("id should be user id");
        if (callback) {
            callback(false);
        }
        return;
    }

    auto q = std::make_shared<query_block_or_unblock_user>(callback);
    q->out_i32(CODE_contacts_unblock);
    q->out_i32(CODE_input_user);
    q->out_i32(id.peer_id);
    q->out_i64(id.access_hash);
    q->execute(active_client());
}

void user_agent::get_blocked_users(const std::function<void(std::vector<int32_t>)>& callback)
{
    auto q = std::make_shared<query_get_blocked_users>(callback);
    q->out_i32(CODE_contacts_get_blocked);
    q->out_i32(0);
    q->out_i32(0);
    q->execute(active_client());
}

void user_agent::update_notify_settings(const tgl_input_peer_t& peer_id,
        int32_t mute_until, const std::string& sound, bool show_previews, int32_t mask,
        const std::function<void(bool)>& callback)
{
    auto q = std::make_shared<query_update_notify_settings>(callback);
    q->out_i32(CODE_account_update_notify_settings);
    q->out_i32(CODE_input_notify_peer);
    q->out_input_peer(this, peer_id);
    q->out_i32(CODE_input_peer_notify_settings);
    q->out_i32(mute_until);
    q->out_std_string(sound);
    q->out_i32(show_previews ? CODE_bool_true : CODE_bool_false);
    q->out_i32(CODE_input_peer_notify_events_all);

    q->execute(active_client());
}

void user_agent::get_notify_settings(const tgl_input_peer_t &peer_id,
        const std::function<void(bool, int32_t mute_until)>& callback)
{
    auto q = std::make_shared<query_get_notify_settings>(callback);
    q->out_i32(CODE_account_get_notify_settings);
    q->out_i32(CODE_input_notify_peer);
    q->out_input_peer(this, peer_id);
    q->execute(active_client());
}

void user_agent::get_terms_of_service(const std::function<void(bool success, const std::string& tos)>& callback)
{
    auto q = std::make_shared<query_get_tos>(callback);
    q->out_i32(CODE_help_get_terms_of_service);
    q->out_string("");
    q->execute(active_client());
}

void user_agent::register_device(int32_t token_type, const std::string& token,
        const std::string& device_model,
        const std::string& system_version,
        const std::string& app_version,
        bool app_sandbox,
        const std::string& lang_code,
        const std::function<void(bool success)>& callback)
{
    m_device_token_type = token_type;
    m_device_token = token;

    auto q = std::make_shared<query_register_device>(callback);
    q->out_i32(CODE_account_register_device);
    q->out_i32(token_type);
    q->out_std_string(token);
    q->out_std_string(device_model);
    q->out_std_string(system_version);
    q->out_std_string(app_version);
    q->out_i32(app_sandbox? CODE_bool_true : CODE_bool_false);
    q->out_std_string(lang_code);
    q->execute(active_client());
}

void user_agent::unregister_device(int32_t token_type, const std::string& token,
        const std::function<void(bool success)>& callback)
{
    auto q = std::make_shared<query_unregister_device>(callback);
    q->out_i32(CODE_account_unregister_device);
    q->out_i32(token_type);
    q->out_std_string(token);
    q->execute(active_client());
}

void user_agent::upgrade_group(const tgl_peer_id_t& id, const std::function<void(bool success)>& callback)
{
    auto q = std::make_shared<query_send_messages>(callback);
    q->out_i32(CODE_messages_migrate_chat);
    q->out_i32(id.peer_id);
    q->execute(active_client());
}

void user_agent::set_client_logged_out(const std::shared_ptr<mtproto_client>& from_client, bool success)
{
    if (from_client->is_logging_out()) {
        auto q = from_client->logout_query();
        q->clear_timers();
        if (q->msg_id()) {
            remove_query(q);
        }
        from_client->set_logout_query(nullptr);
    }

    if (!success) {
        return;
    }

    for (const auto& client: clients()) {
        if (!client) {
            continue;
        }
        if (client->session()) {
            client->clear_session();
        }
        if (client->is_logging_out()) {
            auto q = from_client->logout_query();
            q->clear_timers();
            if (q->msg_id()) {
                remove_query(q);
            }
            from_client->set_logout_query(nullptr);
        }
        client->set_logged_in(false);
    }
    clear_all_locks();

    // Upon de-authorization, the event queue of the
    // corresponding device will be forcibly cleared,
    // and the value of qts will become irrelevant.
    set_qts(0, true);
}

void user_agent::update_status(bool online, const std::function<void(bool success)>& callback)
{
    auto q = std::make_shared<query_update_status>(callback);
    q->out_i32(CODE_account_update_status);
    q->out_i32(online ? CODE_bool_false : CODE_bool_true);
    q->execute(active_client());
}

void user_agent::export_all_auth()
{
    for (const auto& client: clients()) {
        if (client && !client->is_logged_in()) {
            client->transfer_auth_to_me();
        }
    }
}

void user_agent::signed_in()
{
    callback()->logged_in(true);
    export_all_auth();
    if (!is_started()) {
        set_started(true);
        callback()->started();
    }

    std::weak_ptr<user_agent> weak_ua = shared_from_this();
    m_state_lookup_timer = m_timer_factory->create_timer([weak_ua]() {
        if (auto ua = weak_ua.lock()){
            ua->state_lookup_timeout();
        }
    });

    m_state_lookup_timer->start(3600);
}

void user_agent::sign_in_code(const std::string& phone, const std::string& hash, const std::string& code, tgl_login_action action)
{
    std::weak_ptr<user_agent> weak_ua = shared_from_this();

    auto try_again = [weak_ua, phone, hash](const std::string& code, tgl_login_action action) {
        if (auto ua = weak_ua.lock()) {
            ua->sign_in_code(phone, hash, code, action);
        }
    };

    if (action == tgl_login_action::call_me) {
        call_me(phone, hash, nullptr);
        callback()->get_value(std::make_shared<tgl_value_login_code>(try_again));
        return;
    } else if (action == tgl_login_action::resend_code) {
        sign_in_phone(phone);
        return;
    }

    send_code_result(phone, hash, code, [weak_ua, try_again](bool success, const std::shared_ptr<user>&) {
        TGL_DEBUG("sign in result: " << std::boolalpha << success);
        auto ua = weak_ua.lock();
        if (!ua) {
            TGL_ERROR("the user agent has gone");
            return;
        }
        if (!success) {
            TGL_ERROR("incorrect code");
            ua->callback()->get_value(std::make_shared<tgl_value_login_code>(try_again));
            return;
        }
        ua->signed_in();
    });
}

void user_agent::sign_up_code(const std::string& phone, const std::string& hash,
        const std::string& first_name, const std::string& last_name, const std::string& code, tgl_login_action action)
{
    std::weak_ptr<user_agent> weak_ua = shared_from_this();
    auto try_again = [weak_ua, phone, hash, first_name, last_name](const std::string& code, tgl_login_action action) {
        if (auto ua = weak_ua.lock()) {
            ua->sign_up_code(phone, hash, first_name, last_name, code, action);
        }
    };

    if (action == tgl_login_action::call_me) {
        call_me(phone, hash, nullptr);
        callback()->get_value(std::make_shared<tgl_value_login_code>(try_again));
        return;
    } else if (action == tgl_login_action::resend_code) {
        sign_in_phone(phone); // there is no sign_up_phone(), so this is okay
        return;
    }

    auto q = std::make_shared<query_sign_in>([weak_ua, try_again](bool success, const std::shared_ptr<user>&) {
        auto ua = weak_ua.lock();
        if (!ua) {
            TGL_ERROR("the user agent has gone");
            return;
        }

        if (!success) {
            TGL_ERROR("incorrect code");
            ua->callback()->get_value(std::make_shared<tgl_value_login_code>(try_again));
            return;
        }
        ua->signed_in();
    });

    q->out_i32(CODE_auth_sign_up);
    q->out_std_string(phone);
    q->out_std_string(hash);
    q->out_std_string(code);
    q->out_std_string(first_name);
    q->out_std_string(last_name);
    q->execute(active_client(), query::execution_option::LOGIN);
}

void user_agent::register_me(const std::string& phone, const std::string& hash,
        bool register_user, const std::string& first_name, const std::string& last_name)
{
    if (register_user) {
        std::weak_ptr<user_agent> weak_ua = shared_from_this();
        if (first_name.size() >= 1) {
            callback()->get_value(std::make_shared<tgl_value_login_code>(
                    [weak_ua, phone, hash, first_name, last_name](const std::string& code, tgl_login_action action) {
                        if (auto ua = weak_ua.lock()) {
                            ua->sign_up_code(phone, hash, first_name, last_name, code, action);
                        }
                    }));
        } else {
            callback()->get_value(std::make_shared<tgl_value_register_info>(
                    [weak_ua, phone, hash](bool register_user, const std::string& first_name, const std::string& last_name) {
                        if (auto ua = weak_ua.lock()) {
                            ua->register_me(phone, hash, register_user, first_name, last_name);
                        }
                    }));
        }
    } else {
        TGL_ERROR("stopping registration");
        login();
    }
}

void user_agent::sign_in_phone(const std::string& phone)
{
    std::weak_ptr<user_agent> weak_ua = shared_from_this();

    set_phone_number_input_locked(true);

    send_code(phone, [weak_ua, phone](bool success, bool registered, const std::string& hash) {
        auto ua = weak_ua.lock();
        if (!ua) {
            TGL_ERROR("the user agent has gone");
            return;
        }

        ua->set_phone_number_input_locked(false);

        if (!success) {
            ua->callback()->logged_in(false);
            ua->callback()->get_value(std::make_shared<tgl_value_phone_number>(
                    [weak_ua](const std::string& phone) {
                        if (auto ua = weak_ua.lock()) {
                            ua->sign_in_phone(phone);
                        }
                    }));
            return;
        }

        if (registered) {
            TGL_DEBUG("already registered, need code");
            ua->callback()->get_value(std::make_shared<tgl_value_login_code>(
                    [weak_ua, phone, hash](const std::string& code, tgl_login_action action) {
                        if (auto ua = weak_ua.lock()) {
                            ua->sign_in_code(phone, hash, code, action);
                        }
                    }));
        } else {
            TGL_DEBUG("not registered");
            ua->callback()->get_value(std::make_shared<tgl_value_register_info>(
                    [weak_ua, phone, hash](bool register_user, const std::string& first_name, const std::string& last_name) {
                        if (auto ua = weak_ua.lock()) {
                            ua->register_me(phone, hash, register_user, first_name, last_name);
                        }
                    }));
        }
    });
}

void user_agent::sign_in()
{
    assert(!active_client()->is_logged_in());

    if (is_phone_number_input_locked()) {
        TGL_ERROR("phone number input is locked");
        return;
    }

    TGL_DEBUG("asking for phone number");
    std::weak_ptr<user_agent> weak_ua = shared_from_this();
    callback()->get_value(std::make_shared<tgl_value_phone_number>(
            [weak_ua](const std::string& phone) {
                if (auto ua = weak_ua.lock()) {
                    ua->sign_in_phone(phone);
                }
            }));
}

void user_agent::login()
{
    auto client = active_client();
    if (!client) {
        TGL_ERROR("no working dc set, can't log in");
        return;
    }

    if (!client->is_authorized()) {
        client->restart_authorization();
    }

    if (client->is_logged_in()) {
        signed_in();
        return;
    }

    sign_in();
}

void user_agent::set_phone_number(const std::string& phonenumber, const std::function<void(bool success)>& callback)
{
    std::shared_ptr<change_phone_state> state = std::make_shared<change_phone_state>();
    state->phone = phonenumber;
    state->callback = callback;
    state->weak_user_agent = std::weak_ptr<user_agent>(shared_from_this());

    auto q = std::make_shared<query_send_change_code>(std::bind(tgl_set_phone_number_cb, state, std::placeholders::_1, std::placeholders::_2));
    q->out_header(this);
    q->out_i32(CODE_account_send_change_phone_code);
    q->out_std_string(state->phone);
    q->execute(active_client());
}


void user_agent::get_privacy_rules(std::function<void(bool, const std::vector<std::pair<tgl_privacy_rule, const std::vector<int32_t>>>&)> callback)
{
    auto q = std::make_shared<query_get_privacy_rules>(callback);
    q->out_i32(CODE_account_get_privacy);
    q->out_i32(CODE_input_privacy_key_status_timestamp);
    q->execute(active_client());
}

void user_agent::send_inline_query_to_bot(const tgl_input_peer_t& bot, const std::string& query,
        const std::function<void(bool success, const std::string& response)>& callback)
{
    auto q = std::make_shared<query_send_inline_query_to_bot>(callback);
    q->out_i32(CODE_messages_get_inline_bot_results);
    q->out_input_peer(this, bot);
    q->out_std_string(query);
    q->out_std_string(std::string());
    q->execute(active_client());
}

void user_agent::set_secret_chat_ttl(const tgl_input_peer_t& chat_id, int ttl)
{
    auto sc = secret_chat_for_id(chat_id);
    if (!sc) {
        TGL_ERROR("the secret chat " << chat_id.peer_id << " has gone");
        return;
    }
    struct tl_ds_decrypted_message_action action;
    action.magic = CODE_decrypted_message_action_set_message_ttl;
    action.ttl_seconds = &ttl;

    std::static_pointer_cast<secret_chat>(sc)->send_action(action, 0, nullptr);
}

void user_agent::send_accept_encr_chat(const std::shared_ptr<secret_chat>& sc,
        std::array<unsigned char, 256>& random,
        const std::function<void(bool, const std::shared_ptr<secret_chat>&)>& callback)
{
    bool ok = false;
    const int* key = reinterpret_cast<const int*>(sc->key());
    for (int i = 0; i < 64; i++) {
        if (key[i]) {
            ok = true;
            break;
        }
    }
    if (ok) {
        // Already generated key for this chat
        if (callback) {
            callback(true, sc);
        }
        return;
    }

    assert(!sc->g_key().empty());
    assert(bn_ctx()->ctx);
    unsigned char random_here[256];
    tgl_secure_random(random_here, 256);
    for (int i = 0; i < 256; i++) {
        random[i] ^= random_here[i];
    }
    std::unique_ptr<TGLC_bn, TGLC_bn_clear_deleter> b(TGLC_bn_bin2bn(random.data(), 256, 0));
    std::unique_ptr<TGLC_bn, TGLC_bn_clear_deleter> g_a(TGLC_bn_bin2bn(sc->g_key().data(), 256, 0));
    if (tglmp_check_g_a(sc->encr_prime_bn()->bn, g_a.get()) < 0) {
        if (callback) {
            callback(false, sc);
        }
        sc->set_deleted();
        return;
    }

    TGLC_bn* p = sc->encr_prime_bn()->bn;
    std::unique_ptr<TGLC_bn, TGLC_bn_clear_deleter> r(TGLC_bn_new());
    check_crypto_result(TGLC_bn_mod_exp(r.get(), g_a.get(), b.get(), p, bn_ctx()->ctx));
    unsigned char buffer[256];
    memset(buffer, 0, sizeof(buffer));
    TGLC_bn_bn2bin(r.get(), buffer + (256 - TGLC_bn_num_bytes(r.get())));

    sc->set_key(buffer);
    sc->set_state(tgl_secret_chat_state::ok);

    memset(buffer, 0, sizeof(buffer));
    check_crypto_result(TGLC_bn_set_word(g_a.get(), sc->encr_root()));
    check_crypto_result(TGLC_bn_mod_exp(r.get(), g_a.get(), b.get(), p, bn_ctx()->ctx));
    TGLC_bn_bn2bin(r.get(), buffer + (256 - TGLC_bn_num_bytes(r.get())));

    auto q = std::make_shared<query_messages_accept_encryption>(sc, callback);
    q->out_i32(CODE_messages_accept_encryption);
    q->out_i32(CODE_input_encrypted_chat);
    q->out_i32(sc->id().peer_id);
    q->out_i64(sc->id().access_hash);
    q->out_string(reinterpret_cast<const char*>(buffer), 256);
    q->out_i64(sc->key_fingerprint());
    q->execute(active_client());
}

void user_agent::send_create_encr_chat(const tgl_input_peer_t& user_id,
        const std::shared_ptr<secret_chat>& sc,
        std::array<unsigned char, 256>& random,
        const std::function<void(bool, const std::shared_ptr<secret_chat>&)>& callback)
{
    unsigned char random_here[256];
    tgl_secure_random(random_here, 256);
    for (int i = 0; i < 256; i++) {
        random[i] ^= random_here[i];
    }

    std::unique_ptr<TGLC_bn, TGLC_bn_clear_deleter> a(TGLC_bn_bin2bn(random.data(), 256, 0));
    TGLC_bn* p = sc->encr_prime_bn()->bn;

    std::unique_ptr<TGLC_bn, TGLC_bn_clear_deleter> g(TGLC_bn_new());
    check_crypto_result(TGLC_bn_set_word(g.get(), sc->encr_root()));

    std::unique_ptr<TGLC_bn, TGLC_bn_clear_deleter> r(TGLC_bn_new());

    check_crypto_result(TGLC_bn_mod_exp(r.get(), g.get(), a.get(), p, bn_ctx()->ctx));

    char g_a[256];
    memset(g_a, 0, sizeof(g_a));

    TGLC_bn_bn2bin(r.get(), reinterpret_cast<unsigned char*>(g_a + (256 - TGLC_bn_num_bytes(r.get()))));

    sc->set_admin_id(our_id().peer_id);
    sc->set_key(random.data());
    sc->set_state(tgl_secret_chat_state::waiting);
    m_callback->secret_chat_update(sc);

    auto q = std::make_shared<query_messages_request_encryption>(sc, callback);
    q->out_i32(CODE_messages_request_encryption);
    q->out_i32(CODE_input_user);
    q->out_i32(user_id.peer_id);
    q->out_i64(user_id.access_hash);
    q->out_i32(sc->id().peer_id);
    q->out_string(g_a, sizeof(g_a));
    q->execute(active_client());
}

void user_agent::discard_secret_chat(const tgl_input_peer_t& chat_id,
        const std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)>& callback)
{
    auto sc = secret_chat_for_id(chat_id);
    if (!sc || sc->state() == tgl_secret_chat_state::deleted) {
        if (callback) {
            callback(true, sc);
        }
        return;
    }

    auto q = std::make_shared<query_messages_discard_encryption>(sc, callback);
    q->out_i32(CODE_messages_discard_encryption);
    q->out_i32(sc->id().peer_id);

    q->execute(active_client());
}

void user_agent::accept_encr_chat_request(const tgl_input_peer_t& chat_id,
        const std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)>& callback)
{
    auto sc = secret_chat_for_id(chat_id);
    if (!sc || sc->state() != tgl_secret_chat_state::request) {
        if (callback) {
            callback(false, sc);
        }
        return;
    }

    std::weak_ptr<user_agent> weak_ua = shared_from_this();
    auto q = std::make_shared<query_messages_get_dh_config>(sc,
            [weak_ua](const std::shared_ptr<secret_chat>& sc,
                    std::array<unsigned char, 256>& random,
                    const std::function<void(bool, const std::shared_ptr<secret_chat>&)>& cb)
            {
                if (auto ua = weak_ua.lock()) {
                    ua->send_accept_encr_chat(sc, random, cb);
                } else {
                    TGL_ERROR("the user agent has gone");
                    if (cb) {
                        cb(false, nullptr);
                    }
                }
            }, callback);

    q->out_i32(CODE_messages_get_dh_config);
    q->out_i32(sc->encr_param_version());
    q->out_i32(256);
    q->execute(active_client());
}

void user_agent::create_secret_chat(const tgl_input_peer_t& user_id, int32_t new_secret_chat_id,
        const std::function<void(bool success, const std::shared_ptr<tgl_secret_chat>&)>& callback)
{
    std::shared_ptr<secret_chat> sc = allocate_secret_chat(
            tgl_input_peer_t(tgl_peer_type::enc_chat, new_secret_chat_id, 0), user_id.peer_id);

    if (!sc) {
        if (callback) {
            callback(false, nullptr);
        }
    }

    std::weak_ptr<user_agent> weak_ua = shared_from_this();
    auto q = std::make_shared<query_messages_get_dh_config>(sc,
            [weak_ua, user_id](const std::shared_ptr<secret_chat>& sc,
                    std::array<unsigned char, 256>& random,
                    const std::function<void(bool, const std::shared_ptr<secret_chat>&)>& cb)
            {
                if (auto ua = weak_ua.lock()) {
                    ua->send_create_encr_chat(user_id, sc, random, cb);
                } else {
                    TGL_ERROR("the user agent has gone");
                    if (cb) {
                        cb(false, nullptr);
                    }
                }
            }, callback, 10.0);

    q->out_i32(CODE_messages_get_dh_config);
    q->out_i32(0);
    q->out_i32(256);
    q->execute(active_client());
}

void user_agent::bytes_sent(size_t bytes)
{
    m_bytes_sent += bytes;
}

void user_agent::bytes_received(size_t bytes)
{
    m_bytes_received += bytes;
}

tgl_net_stats user_agent::get_net_stats(bool reset_after_get)
{
    tgl_net_stats stats;
    stats.bytes_sent = m_bytes_sent;
    stats.bytes_received = m_bytes_received;
    if (reset_after_get) {
        m_bytes_sent = 0;
        m_bytes_received = 0;
    }
    return stats;
}

void user_agent::user_fetched(const std::shared_ptr<user>& u)
{
    if (u->is_self()) {
        set_our_id(u->id().peer_id);
    }

    if (u->is_deleted()) {
        m_callback->user_deleted(u->id().peer_id);
    } else {
        m_callback->new_user(u);
        m_callback->avatar_update(u->id().peer_id, u->id().peer_type, u->photo_small(), u->photo_big());
    }
}

void user_agent::chat_fetched(const std::shared_ptr<chat>& c)
{
    if (c->is_channel()) {
        m_callback->channel_update(std::static_pointer_cast<channel>(c));
    } else {
        m_callback->chat_update(c);
    }

    m_callback->avatar_update(c->id().peer_id, c->id().peer_type, c->photo_big(), c->photo_small());
}

}
}
