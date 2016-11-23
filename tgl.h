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
#ifndef __TGL_H__
#define __TGL_H__

#include "crypto/tgl_crypto_bn.h"
#include "types/tgl_online_status.h"
#include "types/tgl_peer_id.h"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <stdlib.h>
#include <string.h>
#include <vector>


class tgl_connection;
class tgl_online_status_observer;
struct tgl_session;
struct tgl_dc;
class query;
struct tgl_user;
struct tgl_state;

enum class tgl_value_type {
    phone_number,           // user phone number
    code,                   // telegram login code, or 'call' for phone call request
    register_info,          // "Y/n" register?, first name, last name
    new_password,           // new pass, confirm new pass
    cur_and_new_password,   // curr pass, new pass, confirm new pass
    cur_password,           // current pass
    bot_hash,
};

inline static std::string to_string(tgl_value_type type)
{
    switch (type) {
    case tgl_value_type::phone_number:
        return "phone_number";
    case tgl_value_type::code:
        return "code";
    case tgl_value_type::register_info:
        return "register_info";
    case tgl_value_type::new_password:
        return "new_password";
    case tgl_value_type::cur_and_new_password:
        return "cur_and_new_password";
    case tgl_value_type::cur_password:
        return "cur_password";
    case tgl_value_type::bot_hash:
        return "bot_hash";
    default:
        assert(false);
        return "unknown tgl value type";
    }
}

inline std::ostream& operator<<(std::ostream& os, tgl_value_type type)
{
    os << to_string(type);
    return os;
}

enum class tgl_user_update_type: int8_t {
    firstname = 0,
    lastname,
    username,
    phone,
    blocked
};

enum class tgl_user_status_type {
    offline,
    online,
    recently,
    last_week,
    last_month,
};

class tgl_transfer_manager;
class tgl_connection_factory;
class tgl_rsa_key;
class tgl_timer;
class tgl_timer_factory;
class tgl_update_callback;
struct tgl_message;
struct tgl_secret_chat;

struct tgl_state {
    static tgl_state* instance();

    static void reset();

    bool is_started() const { return m_is_started; }
    void set_started(bool b) { m_is_started = b; }

    const std::vector<std::shared_ptr<tgl_dc>>& dcs() { return m_dcs; }
    std::shared_ptr<tgl_dc> working_dc() { return m_working_dc; }
    std::shared_ptr<tgl_dc> allocate_dc(int id);
    std::shared_ptr<tgl_dc> dc_at(int id);
    int temp_key_expire_time() const { return m_temp_key_expire_time; }

    int init(const std::string& download_dir, int app_id, const std::string& app_hash, const std::string& app_version);
    void login();
    void logout();

    TGLC_bn_ctx* bn_ctx() { return m_bn_ctx.get(); }

    void set_auth_key(int num, const char* buf);
    void set_our_id(int id);
    void set_dc_option(bool is_v6, int id, const std::string& ip, int port);
    void set_dc_logged_in(int num);
    void set_working_dc(int num);
    void set_qts(int32_t qts, bool force = false);
    void set_pts(int32_t pts, bool force = false);
    void set_date(int64_t date, bool force = false);
    void set_seq(int32_t seq);
    void reset_server_state();
    void set_callback(const std::shared_ptr<tgl_update_callback>& cb) { m_callback = cb; }
    void add_rsa_key(const std::string& key);
    void set_enable_pfs(bool); // enable perfect forward secrecy (does not work properly right now)
    void set_test_mode(bool);
    void set_connection_factory(const std::shared_ptr<tgl_connection_factory>& factory) { m_connection_factory = factory; }
    void set_timer_factory(const std::shared_ptr<tgl_timer_factory>& factory) { m_timer_factory = factory; }
    void set_enable_ipv6(bool val);

    tgl_online_status online_status() const { return m_online_status; }
    void set_online_status(tgl_online_status status);
    void add_online_status_observer(const std::weak_ptr<tgl_online_status_observer>& observer)
    {
        m_online_status_observers.insert(observer);
    }

    void remove_online_status_observer(const std::weak_ptr<tgl_online_status_observer>& observer)
    {
        m_online_status_observers.erase(observer);
    }

    const std::string& app_version() const { return m_app_version; }
    const std::string& app_hash() const { return m_app_hash; }
    int32_t app_id() const { return m_app_id; }
    const std::vector<std::shared_ptr<tgl_rsa_key>>& rsa_key_list() const { return m_rsa_key_list; }

    const std::shared_ptr<tgl_transfer_manager>& transfer_manager() const { return m_transfer_manager; }
    const std::shared_ptr<tgl_connection_factory>& connection_factory() const { return m_connection_factory; }
    const std::shared_ptr<tgl_timer_factory>& timer_factory() const { return m_timer_factory; }
    const std::shared_ptr<tgl_update_callback>& callback() const { return m_callback; }

    void set_error(const std::string& error, int error_code);

    int32_t pts() const { return m_pts; }
    int32_t qts() const { return m_qts; }
    int32_t seq() const { return m_seq; }
    int64_t date() const { return m_date; }
    bool test_mode() const { return m_test_mode; }
    const tgl_peer_id_t& our_id() const { return m_our_id; }
    bool ipv6_enabled() const { return m_ipv6_enabled; }
    bool pfs_enabled() const { return m_enable_pfs; }

    std::shared_ptr<tgl_secret_chat> secret_chat_for_id(const tgl_input_peer_t& id) const
    {
        return secret_chat_for_id(id.peer_id);
    }
    int32_t create_secret_chat_id();
    std::shared_ptr<tgl_secret_chat> create_secret_chat(int32_t new_chat_id);
    std::shared_ptr<tgl_secret_chat> create_secret_chat(const tgl_input_peer_t& chat_id);
    std::shared_ptr<tgl_secret_chat> secret_chat_for_id(int chat_id) const;
    void add_secret_chat(const std::shared_ptr<tgl_secret_chat>& secret_chat);

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
    void clear_all_locks()
    {
        m_diff_locked = false;
        m_password_locked = false;
        m_phone_number_input_locked = false;
    }

private:
    tgl_state();
    static void state_lookup_timeout();

private:
    tgl_online_status m_online_status;

    int32_t m_app_id;
    std::string m_app_hash;

    std::string m_error;
    int m_error_code;

    int m_temp_key_expire_time;

    int32_t m_pts;
    int32_t m_qts;
    int64_t m_date;
    int32_t m_seq;

    bool m_is_started;
    bool m_test_mode; // Connects to the telegram test servers instead of the regular servers
    bool m_enable_pfs;
    bool m_ipv6_enabled;
    bool m_diff_locked;
    bool m_password_locked;
    bool m_phone_number_input_locked;

    tgl_peer_id_t m_our_id; // ID of logged in user
    std::string m_app_version;
    std::vector<std::shared_ptr<tgl_rsa_key>> m_rsa_key_list;
    std::map<int32_t/*peer id*/, std::shared_ptr<tgl_secret_chat>> m_secret_chats;
    std::map<int64_t/*msg_id*/, std::shared_ptr<query>> m_active_queries;

    std::shared_ptr<tgl_transfer_manager> m_transfer_manager;
    std::shared_ptr<tgl_timer_factory> m_timer_factory;
    std::shared_ptr<tgl_connection_factory> m_connection_factory;
    std::shared_ptr<tgl_update_callback> m_callback;

    std::unique_ptr<TGLC_bn_ctx, TGLC_bn_ctx_deleter> m_bn_ctx;

    std::vector<std::shared_ptr<tgl_dc>> m_dcs;
    std::shared_ptr<tgl_dc> m_working_dc;
    std::shared_ptr<tgl_timer> m_state_lookup_timer;
    std::set<std::weak_ptr<tgl_online_status_observer>, std::owner_less<std::weak_ptr<tgl_online_status_observer>>> m_online_status_observers;

    static std::unique_ptr<tgl_state> s_instance;
};

void tgl_do_lookup_state();

#endif
