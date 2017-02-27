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

#ifndef __TGL_USER_AGENT_H__
#define __TGL_USER_AGENT_H__

#include "tgl_online_status.h"
#include "tgl_online_status_observer.h"
#include "tgl_query_api.h"
#include "tgl_secret_chat.h"

#include <cstdint>
#include <memory>
#include <string>

class tgl_connection_factory;
class tgl_dc;
class tgl_secret_chat;
class tgl_transfer_manager;
class tgl_timer_factory;
class tgl_unconfirmed_secret_message_storage;
class tgl_update_callback;

class tgl_user_agent: public tgl_query_api
{
public:
    static std::shared_ptr<tgl_user_agent> create(const std::vector<std::string>& rsa_keys,
            const std::string& download_dir,
            int app_id, const std::string& app_hash, const std::string& app_version,
            const std::string& device_model, const std::string& system_version, const std::string& lang_code);

    virtual ~tgl_user_agent() { }

    virtual void login() = 0;
    virtual void logout() = 0;
    virtual void shut_down() = 0;

    // Could be null.
    virtual std::shared_ptr<tgl_dc> active_dc() const = 0;

    virtual void set_dc_auth_key(int dc_id, const char* key, size_t key_length) = 0;
    virtual void set_dc_option(bool is_v6, int id, const std::string& ip, int port) = 0;
    virtual void set_dc_logged_in(int dc_id) = 0;
    virtual void set_active_dc(int dc_id) = 0;

    virtual void set_our_id(int32_t id) = 0;
    virtual const tgl_peer_id_t& our_id() const = 0;

    virtual void set_qts(int32_t qts, bool force = false) = 0;
    virtual void set_pts(int32_t pts, bool force = false) = 0;
    virtual void set_date(int64_t date, bool force = false) = 0;
    virtual void set_test_mode(bool) = 0;
    virtual bool test_mode() const = 0;

    virtual void set_pfs_enabled(bool) = 0;
    virtual void set_ipv6_enabled(bool) = 0;

    virtual void reset_authorization() = 0;
    virtual void add_rsa_key(const std::string& key) = 0;

    virtual tgl_online_status online_status() const = 0;
    virtual void set_online_status(tgl_online_status status) = 0;
    virtual void add_online_status_observer(const std::weak_ptr<tgl_online_status_observer>& observer) = 0;
    virtual void remove_online_status_observer(const std::weak_ptr<tgl_online_status_observer>& observer) = 0;

    virtual const std::string& app_version() const = 0;
    virtual const std::string& app_hash() const = 0;
    virtual int32_t app_id() const = 0;
    virtual const std::string& device_model() const = 0;
    virtual const std::string& system_version() const = 0;
    virtual const std::string& lang_code() const = 0;

    virtual void set_callback(const std::shared_ptr<tgl_update_callback>& cb) = 0;
    virtual void set_connection_factory(const std::shared_ptr<tgl_connection_factory>& factory) = 0;
    virtual void set_timer_factory(const std::shared_ptr<tgl_timer_factory>& factory) = 0;
    virtual tgl_transfer_manager* transfer_manager() const = 0;
    virtual void set_unconfirmed_secret_message_storage(const std::shared_ptr<tgl_unconfirmed_secret_message_storage>& storage) = 0;

    virtual int32_t create_secret_chat_id() const = 0;

    virtual std::shared_ptr<tgl_secret_chat> load_secret_chat(int32_t chat_id, int64_t access_hash, int32_t user_id,
            int32_t admin, int32_t date, int32_t ttl, int32_t layer,
            int32_t in_seq_no, int32_t out_seq_no,
            int32_t encr_root, int32_t encr_param_version,
            tgl_secret_chat_state state, tgl_secret_chat_exchange_state exchange_state,
            int64_t exchange_id,
            const unsigned char* key, size_t key_length,
            const unsigned char* encr_prime, size_t encr_prime_length,
            const unsigned char* g_key, size_t g_key_length,
            const unsigned char* exchange_key, size_t exchange_key_length) = 0;
};

#endif
