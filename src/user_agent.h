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
#pragma once

#include "tgl/tgl_connection_status.h"
#include "tgl/tgl_online_status.h"
#include "tgl/tgl_peer_id.h"
#include "tgl/tgl_query_api.h"
#include "tgl/tgl_user_agent.h"
#include "tgl/tgl_value.h"
#include "updater.h"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <stdlib.h>
#include <string.h>
#include <vector>

class query;
struct tgl_user;
struct tl_ds_dc_option;

class mtproto_client;

class tgl_rsa_key;
class tgl_timer;
struct tgl_bn_context;

class user_agent: public std::enable_shared_from_this<user_agent>, public tgl_user_agent
{
public:
    user_agent();

    // == tgl_user_agent ==
    virtual int32_t app_id() const override { return m_app_id; }
    virtual const std::string& app_version() const override { return m_app_version; };
    virtual const std::string& app_hash() const override { return m_app_hash; }
    virtual const std::string& device_model() const override { return m_device_model; }
    virtual const std::string& system_version() const override { return m_system_version; }
    virtual const std::string& lang_code() const override { return m_lang_code; }

    virtual void login() override;
    virtual void logout() override;
    virtual void shut_down() override;

    virtual std::shared_ptr<tgl_dc> active_dc() const override;

    virtual void set_dc_auth_key(int dc_id, const char* key, size_t key_length) override; 
    virtual void set_dc_option(bool is_v6, int id, const std::string& ip, int port) override;
    virtual void set_dc_logged_in(int dc_id) override { set_dc_logged_in(dc_id, true); }
    virtual void set_active_dc(int dc_id) override;

    virtual void set_our_id(int32_t id) override;
    virtual const tgl_peer_id_t& our_id() const override { return m_our_id; }

    virtual void set_qts(int32_t qts, bool force = false) override;
    virtual void set_pts(int32_t pts, bool force = false) override;

    virtual void set_date(int64_t date, bool force = false) override;
    virtual void set_test_mode(bool b) override { m_test_mode = b; }
    virtual bool test_mode() const override { return m_test_mode; }
    virtual void set_pfs_enabled(bool b) override { m_pfs_enabled = b; }
    virtual void set_ipv6_enabled(bool b) override { m_ipv6_enabled = b; }

    virtual void reset_authorization() override;
    virtual void add_rsa_key(const std::string& key) override;

    virtual tgl_online_status online_status() const override { return m_online_status; }
    virtual void set_online_status(tgl_online_status status) override;
    virtual void add_online_status_observer(const std::weak_ptr<tgl_online_status_observer>& observer) override;
    virtual void remove_online_status_observer(const std::weak_ptr<tgl_online_status_observer>& observer) override;

    virtual void set_callback(const std::shared_ptr<tgl_update_callback>& cb) override { m_callback = cb; }

    virtual void set_connection_factory(const std::shared_ptr<tgl_connection_factory>& factory) override { m_connection_factory = factory; }

    virtual void set_timer_factory(const std::shared_ptr<tgl_timer_factory>& factory) override { m_timer_factory = factory; }

    virtual tgl_transfer_manager* transfer_manager() const override { return m_transfer_manager.get(); }
    virtual void set_unconfirmed_secret_message_storage(const std::shared_ptr<tgl_unconfirmed_secret_message_storage>& storage) override;
    virtual int32_t create_secret_chat_id() const override;

    virtual std::shared_ptr<tgl_secret_chat> load_secret_chat(int32_t chat_id, int64_t access_hash, int32_t user_id,
            int32_t admin, int32_t date, int32_t ttl, int32_t layer,
            int32_t in_seq_no, int32_t out_seq_no,
            int32_t encr_root, int32_t encr_param_version,
            tgl_secret_chat_state state, tgl_secret_chat_exchange_state exchange_state,
            int64_t exchange_id,
            const unsigned char* key, size_t key_length,
            const unsigned char* encr_prime, size_t encr_prime_length,
            const unsigned char* g_key, size_t g_key_length,
            const unsigned char* exchange_key, size_t exchange_key_length) override;

    virtual tgl_net_stats get_net_stats(bool reset_after_get = true) override;
    // == tgl_user_agent ==

    // == tgl_query_api ==
    virtual void get_terms_of_service(const std::function<void(bool success, const std::string&)>& callback) override;
    virtual void register_device(int32_t token_type, const std::string& token,
            const std::string& device_model,
            const std::string& system_version,
            const std::string& app_version,
            bool app_sandbox,
            const std::string& lang_code,
            const std::function<void(bool success)>& callback) override;
    virtual void unregister_device(int32_t token_type, const std::string& token,
            const std::function<void(bool success)>& callback) override;
    virtual void update_password_settings(const std::function<void(bool success)>& callback) override;
    virtual int64_t send_text_message(const tgl_input_peer_t& peer_id, const std::string& text, int64_t message_id = 0,
            int32_t reply_id = 0, bool disable_preview = false, bool post_as_channel_message = false,
            bool send_as_secret_chat_service_message = false,
            const std::shared_ptr<tl_ds_reply_markup>& reply_markup = nullptr,
            const std::function<void(bool success, const std::shared_ptr<tgl_message>& message)>& callback = nullptr) override;
    virtual void forward_message(const tgl_input_peer_t& from_id, const tgl_input_peer_t& to_id, int64_t message_id,
            const std::function<void(bool success, const std::shared_ptr<tgl_message>& M)>& callback) override;
    virtual void forward_messages(const tgl_input_peer_t& from_id, const tgl_input_peer_t& to_id, const std::vector<int64_t>& message_ids,
            bool post_as_channel_message, const std::function<void(bool success, const std::vector<std::shared_ptr<tgl_message>>& messages)>& callback) override;
    virtual void mark_message_read(const tgl_input_peer_t& id, int32_t max_id_or_time, const std::function<void(bool success)>& callback) override;
    virtual void send_contact(const tgl_input_peer_t& id,
            const std::string& phone, const std::string& first_name, const std::string& last_name, int32_t reply_id,
            const std::function<void(bool success, const std::shared_ptr<tgl_message>& message)>& callback) override;
    virtual void forward_media(const tgl_input_peer_t& to_id, int64_t message_id, bool post_as_channel_message,
            const std::function<void(bool success, const std::shared_ptr<tgl_message>& message)>& callback) override;
    virtual void send_location(const tgl_input_peer_t& id, double latitude, double longitude, int32_t reply_id = 0, bool post_as_channel_message = false,
            const std::function<void(bool success, const std::shared_ptr<tgl_message>& message)>& callback = nullptr) override;
    virtual void send_broadcast(const std::vector<tgl_input_peer_t>& peers, const std::string& text,
            const std::function<void(bool success, const std::vector<std::shared_ptr<tgl_message>>& messages)>& callback) override;
    virtual void set_profile_name(const std::string& first_name, const std::string& last_name,
            const std::function<void(bool success)>& callback) override;
    virtual void check_username(const std::string& username, const std::function<void(int result)>& callback) override;
    virtual void set_username(const std::string& username, const std::function<void(bool success)>& callback) override;
    virtual void update_status(bool online, const std::function<void(bool success)>& callback) override;
    virtual void export_card(const std::function<void(bool success, const std::vector<int>& card)>& callback) override;
    virtual void rename_chat(const tgl_input_peer_t& id, const std::string& new_title,
            const std::function<void(bool success)>& callback) override;
    virtual void get_chat_info(int32_t id, const std::function<void(bool success)>& callback) override;
    virtual void get_channel_info(const tgl_input_peer_t& id, const std::function<void(bool success)>& callback) override;
    virtual void get_channel_participants(const tgl_input_peer_t& channel_id, int limit, int offset,
            tgl_channel_participant_type type, const std::function<void(bool success)>& callback) override;
    virtual void get_channel_participant_self(const tgl_input_peer_t& channel_id, const std::function<void(bool success)>& callback) override;
    virtual void add_user_to_chat(const tgl_peer_id_t& chat_id, const tgl_input_peer_t& user_id, int32_t limit,
            const std::function<void(bool success)>& callback) override;
    virtual void delete_user_from_chat(int32_t chat_id, const tgl_input_peer_t& user_id,
            const std::function<void(bool success)>& callback) override;
    virtual void create_group_chat(const std::vector<tgl_input_peer_t>& user_ids, const std::string& chat_topic,
            const std::function<void(int32_t chat_id)>& callback) override;
    virtual void export_chat_link(const tgl_peer_id_t& id, const std::function<void(bool success, const std::string& link)>& callback) override;
    virtual void import_chat_link(const std::string& link, const std::function<void(bool success)>& callback) override;
    virtual void get_user_info(const tgl_input_peer_t& id, const std::function<void(bool success, const std::shared_ptr<tgl_user>& user)>& callback) override;
    virtual void add_contacts(const std::vector<std::tuple<std::string, std::string, std::string>>& contacts,
            bool replace, const std::function<void(bool success, const std::vector<int32_t>& user_ids)>& callback) override;
    virtual void delete_contact(const tgl_input_peer_t& id, const std::function<void(bool success)>& callback) override;
    virtual void import_card(int size, int* card, const std::function<void(bool success, const std::shared_ptr<tgl_user>& user)>& callback) override;
    virtual void block_user(const tgl_input_peer_t& id, const std::function<void(bool success)>& callback) override;
    virtual void unblock_user(const tgl_input_peer_t& id, const std::function<void(bool success)>& callback) override;
    virtual void get_blocked_users(const std::function<void(std::vector<int32_t>)>& callback) override;
    virtual void update_notify_settings(const tgl_input_peer_t& peer_id,
            int32_t mute_until, const std::string& sound, bool show_previews, int32_t mask, const std::function<void(bool)>& callback) override;
    virtual void get_notify_settings(const tgl_input_peer_t& peer_id,
            const std::function<void(bool, int32_t mute_until)>& callback) override;
    virtual void accept_encr_chat_request(const std::shared_ptr<tgl_secret_chat>& secret_chat,
            const std::function<void(bool success, const std::shared_ptr<tgl_secret_chat>&)>& callback) override;
    virtual void set_secret_chat_ttl(const std::shared_ptr<tgl_secret_chat>& secret_chat, int32_t ttl) override;
    virtual void discard_secret_chat(const std::shared_ptr<tgl_secret_chat>& secret_chat,
            const std::function<void(bool success, const std::shared_ptr<tgl_secret_chat>&)>& callback) override;
    virtual void create_secret_chat(const tgl_input_peer_t& user_id, int32_t new_secret_chat_id,
            const std::function<void(bool success, const std::shared_ptr<tgl_secret_chat>& secret_chat)>& callback) override;
    virtual void get_dialog_list(int32_t limit, int32_t offset,
            const std::function<void(bool success,
                    const std::vector<tgl_peer_id_t>& peers,
                    const std::vector<int64_t>& last_msg_ids,
                    const std::vector<int32_t>& unread_count)>& callback) override;
    virtual void search_contact(const std::string& username, int limit,
            const std::function<void(const std::vector<std::shared_ptr<tgl_user>>&,
                    const std::vector<std::shared_ptr<tgl_chat>>&)>& callback) override;
    virtual void resolve_username(const std::string& name, const std::function<void(bool success)>& callback) override;
    virtual void update_contact_list(const std::function<void(bool, const std::vector<std::shared_ptr<tgl_user>>&)>& callback) override;
    virtual void get_history(const tgl_input_peer_t& id, int32_t offset, int32_t limit,
            const std::function<void(bool success, const std::vector<std::shared_ptr<tgl_message>>& list)>& callback) override;
    virtual void send_typing(const tgl_input_peer_t& id, enum tgl_typing_status status,
            const std::function<void(bool success)>& callback) override;
    virtual void search_message(const tgl_input_peer_t& id, int32_t from, int32_t to, int32_t limit, int32_t offset, const std::string& query,
            const std::function<void(bool success, const std::vector<std::shared_ptr<tgl_message>>& messages)>& callback) override;
    virtual void delete_message(const tgl_input_peer_t& chat, int64_t message_id, const std::function<void(bool success)>& callback) override;
    virtual void get_message(int64_t message_id,
            const std::function<void(bool success, const std::shared_ptr<tgl_message>& message)>& callback) override;
    virtual void start_bot(const tgl_input_peer_t& bot, const tgl_peer_id_t& chat, const std::string& name,
            const std::function<void(bool success)>& callback) override;
    virtual void set_phone_number(const std::string& phonenumber, const std::function<void(bool success)>& callback) override;
    virtual void get_privacy_rules(std::function<void(bool, const std::vector<std::pair<tgl_privacy_rule, const std::vector<int32_t>>>&)> callback) override;
    virtual void leave_channel(const tgl_input_peer_t& channel_id, const std::function<void(bool success)>& callback) override;
    virtual void delete_channel(const tgl_input_peer_t& channel_id, const std::function<void(bool success)>& callback) override;
    virtual void channel_invite_user(const tgl_input_peer_t& channel_id, const std::vector<tgl_input_peer_t>& user_ids,
            const std::function<void(bool success)>& callback) override;
    virtual void channel_delete_user(const tgl_input_peer_t& channel_id, const tgl_input_peer_t& user_id,
            const std::function<void(bool success)>& callback) override;
    virtual void channel_edit_title(const tgl_input_peer_t& channel_id, const std::string& title,
            const std::function<void(bool success)>& callback) override;
    virtual void create_channel(const std::string& topic, const std::string& about,
            bool broadcast, bool mega_group,
            const std::function<void(int32_t channel_id)>& callback) override;
    virtual void send_inline_query_to_bot(const tgl_input_peer_t& bot, const std::string& query,
            const std::function<void(bool success, const std::string& response)>& callback) override;
    virtual void get_difference(bool sync_from_start, const std::function<void(bool success)>& callback) override;
    virtual void rename_channel(const tgl_input_peer_t& id, const std::string& name,
            const std::function<void(bool success)>& callback) override;
    virtual void join_channel(const tgl_input_peer_t& id, const std::function<void(bool success)>& callback) override;
    virtual void channel_set_about(const tgl_input_peer_t& id, const std::string& about,
            const std::function<void(bool success)>& callback) override;
    virtual void channel_set_username(const tgl_input_peer_t& id, const std::string& username,
            const std::function<void(bool success)>& callback) override;
    virtual void get_channel_difference(const tgl_input_peer_t& channel_id,
            const std::function<void(bool success)>& callback) override;
    virtual void export_channel_link(const tgl_input_peer_t& id,
            const std::function<void(bool success, const std::string& link)>& callback) override;
    virtual void upgrade_group(const tgl_peer_id_t& id, const std::function<void(bool success)>& callback) override;
    virtual void get_channels_dialog_list(int limit, int offset,
            const std::function<void(bool success,
                    const std::vector<tgl_peer_id_t>& peers,
                    const std::vector<int64_t>& last_msg_ids,
                    const std::vector<int>& unread_count)>& callback) override;
    // == tgl_query_api ==

    // FIXME: expose to tgl_query_api once we have a enum for type.
    void channel_set_admin(const tgl_input_peer_t& channel_id, const tgl_input_peer_t& user_id, int type,
            const std::function<void(bool success)>& callback);

    // == internal ==
    int32_t qts() const { return m_qts; }
    int32_t pts() const { return m_pts; }
    int64_t date() const { return m_date; }

    bool pfs_enabled() const { return m_pfs_enabled; }
    bool ipv6_enabled() const { return m_ipv6_enabled; }

    const std::shared_ptr<tgl_update_callback>& callback() const { return m_callback; }
    const std::shared_ptr<tgl_connection_factory>& connection_factory() const { return m_connection_factory; }
    const std::shared_ptr<tgl_timer_factory>& timer_factory() const { return m_timer_factory; }
    const std::shared_ptr<tgl_unconfirmed_secret_message_storage> unconfirmed_secret_message_storage() const;

    bool is_started() const { return m_is_started; }
    void set_started(bool b) { m_is_started = b; }

    class updater& updater() const { return *m_updater; }

    const std::vector<std::shared_ptr<mtproto_client>>& clients() const { return m_clients; }
    std::shared_ptr<mtproto_client> active_client() const { return m_active_client; }
    std::shared_ptr<mtproto_client> client_at(int id) const;
    int temp_key_expire_time() const { return m_temp_key_expire_time; }

    const tgl_bn_context* bn_ctx() const { return m_bn_ctx.get(); }

    void set_seq(int32_t seq);
    int32_t seq() const { return m_seq; }

    const std::vector<std::shared_ptr<tgl_rsa_key>>& rsa_keys() const { return m_rsa_keys; }

    std::shared_ptr<tgl_secret_chat> secret_chat_for_id(const tgl_input_peer_t& id) const { return secret_chat_for_id(id.peer_id); }

    std::shared_ptr<tgl_secret_chat> allocate_secret_chat(const tgl_input_peer_t& chat_id, int32_t user_id);
    std::shared_ptr<tgl_secret_chat> secret_chat_for_id(int chat_id) const;
    const std::map<int32_t, std::shared_ptr<tgl_secret_chat>>& secret_chats() const { return m_secret_chats; }

    void add_query(const std::shared_ptr<query>& q);
    std::shared_ptr<query> get_query(int64_t id) const;
    void remove_query(const std::shared_ptr<query>& q);
    void remove_all_queries();

    bool is_diff_locked() const { return m_diff_locked; }
    bool is_password_locked() const { return m_password_locked; }
    bool is_phone_number_input_locked() const { return m_phone_number_input_locked; }
    void set_diff_locked(bool b) { m_diff_locked = b; }
    void set_password_locked(bool b) { m_password_locked = b; }
    void set_phone_number_input_locked(bool b) { m_phone_number_input_locked = b; }
    void clear_all_locks();

    void check_password(const std::function<void(bool success)>& callback);
    void set_client_logged_out(const std::shared_ptr<mtproto_client>& from_client, bool success);
    void fetch_dc_option(const tl_ds_dc_option* DS_DO);

    void set_dc_logged_in(int dc_id, bool logged_in);

    // FIXME: merge with remove_query
    void delete_query(int64_t id);

    void bytes_sent(size_t bytes);
    void bytes_received(size_t bytes);

private:
    void state_lookup_timeout();
    std::shared_ptr<mtproto_client> allocate_client(int id);
    void sign_in();
    void signed_in();
    void export_all_auth();
    void send_code(const std::string& phone, const std::function<void(bool, bool, const std::string&)>& callback);
    void send_code_result(const std::string& phone,
            const std::string& hash,
            const std::string& code,
            const std::function<void(bool success, const std::shared_ptr<tgl_user>& user)>& callback);
    void sign_in_code(const std::string& phone, const std::string& hash,
            const std::string& code, tgl_login_action action);
    void register_me(const std::string& phone, const std::string& hash,
            bool register_user, const std::string& first_name, const std::string& last_name);
    void sign_in_phone(const std::string& phone_number);
    void sign_up_code(const std::string& phone, const std::string& hash,
            const std::string& first_name, const std::string& last_name, const std::string& code, tgl_login_action action);
    void lookup_state();

    void send_text_message(const std::shared_ptr<tgl_message>& message, bool disable_preview,
            const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback);
    void mark_encrypted_message_read(const tgl_input_peer_t& id, int32_t max_time,
            const std::function<void(bool success)>& callback);
    void send_accept_encr_chat(const std::shared_ptr<tgl_secret_chat>& secret_chat,
            std::array<unsigned char, 256>& random,
            const std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)>& callback);
    void send_create_encr_chat(const tgl_input_peer_t& user_id,
            const std::shared_ptr<tgl_secret_chat>& secret_chat,
            std::array<unsigned char, 256>& random,
            const std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)>& callback);
    void call_me(const std::string& phone, const std::string& hash,
            const std::function<void(bool)>& callback);
    void password_got(const std::string& current_salt, const std::string& password,
            const std::function<void(bool)>& callback);

private:
    friend class tgl_user_agent;
    tgl_online_status m_online_status;
    tgl_peer_id_t m_our_id;

    int64_t m_date;
    int32_t m_pts;
    int32_t m_qts;
    int32_t m_seq;

    int32_t m_app_id;
    int32_t m_temp_key_expire_time;

    uint64_t m_bytes_sent;
    uint64_t m_bytes_received;

    bool m_is_started;
    bool m_test_mode;
    bool m_pfs_enabled;
    bool m_ipv6_enabled;
    bool m_diff_locked;
    bool m_password_locked;
    bool m_phone_number_input_locked;

    int32_t m_device_token_type;
    std::string m_device_token;

    std::string m_app_version;
    std::string m_app_hash;
    std::string m_device_model;
    std::string m_system_version;
    std::string m_lang_code;

    std::shared_ptr<tgl_transfer_manager> m_transfer_manager;
    std::shared_ptr<tgl_timer_factory> m_timer_factory;
    std::shared_ptr<tgl_connection_factory> m_connection_factory;
    std::shared_ptr<tgl_update_callback> m_callback;
    std::shared_ptr<tgl_unconfirmed_secret_message_storage> m_unconfirmed_secret_message_storage;
    std::shared_ptr<mtproto_client> m_active_client;
    std::shared_ptr<tgl_timer> m_state_lookup_timer;

    std::unique_ptr<tgl_bn_context> m_bn_ctx;
    std::unique_ptr<class updater> m_updater;

    std::vector<std::shared_ptr<mtproto_client>> m_clients;
    std::vector<std::shared_ptr<tgl_rsa_key>> m_rsa_keys;
    std::map<int32_t/*peer id*/, std::shared_ptr<tgl_secret_chat>> m_secret_chats;
    std::map<int64_t/*msg_id*/, std::shared_ptr<query>> m_active_queries;
    std::set<std::weak_ptr<tgl_online_status_observer>, std::owner_less<std::weak_ptr<tgl_online_status_observer>>> m_online_status_observers;
};
