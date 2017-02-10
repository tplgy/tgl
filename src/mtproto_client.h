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

    Copyright Nikolay Durov, Andrey Lopatin 2012-2013
              Vitaly Valtman 2013-2015
    Copyright Topology LP 2016
*/
#ifndef __MTPROTO_CLIENT_H__
#define __MTPROTO_CLIENT_H__

#include "crypto/tgl_crypto_bn.h"
#include "tgl/tgl_mtproto_client.h"
#include "tgl/tgl_dc.h"
#include "tgl_session.h"

#include <array>
#include <cassert>
#include <iostream>
#include <list>
#include <memory>
#include <set>
#include <string>
#include <vector>

class tgl_connection;
class tgl_mtproto_client;
class tgl_rsa_key;
class tgl_timer;
class query;

struct encrypted_message;
struct tgl_in_buffer;

class mtproto_client: public std::enable_shared_from_this<mtproto_client>
        , public tgl_mtproto_client
        , public tgl_dc {
public:
    explicit mtproto_client(int32_t id);

    class connection_status_observer {
    public:
        virtual ~connection_status_observer() { }
        virtual void connection_status_changed(tgl_connection_status status) = 0;
    };

    enum class state {
        init,
        reqpq_sent,
        reqdh_sent,
        client_dh_sent,
        init_temp,
        reqpq_sent_temp,
        reqdh_sent_temp,
        client_dh_sent_temp,
        authorized,
        error,
    };

    // From tgl_mtproto_client and tgl_dc
    virtual int32_t id() const override { return m_id; }

    // From tgl_mtproto_client
    virtual void connection_status_changed(const std::shared_ptr<tgl_connection>& c) override;
    virtual bool try_rpc_execute(const std::shared_ptr<tgl_connection>& c) override;
    virtual void ping() override;

    // From tgl_dc
    virtual bool is_logged_in() const override { return m_logged_in; }
    virtual const std::vector<std::pair<std::string, int>>& ipv4_options() const override { return m_ipv4_options; }
    virtual const std::vector<std::pair<std::string, int>>& ipv6_options() const override { return m_ipv6_options; }
    virtual int64_t auth_key_id() const override { return m_auth_key_id; }
    virtual const std::array<unsigned char, 256>& auth_key() const override { return m_auth_key; }
    virtual double time_difference() const override { return m_server_time_delta; }

    const std::shared_ptr<tgl_session>& session() const { return m_session; }

    void clear_session()
    {
        if (m_session) {
            m_session->clear();
            m_session = nullptr;
        }
    }

    void create_session();

    int64_t send_message(const int32_t* msg, int msg_ints,
            int64_t msg_id_override = 0, bool force_send = false, bool useful = false);

    void reset_authorization();
    void restart_authorization();
    void restart_temp_authorization();

    void increase_active_queries(size_t num = 1);
    void decrease_active_queries(size_t num = 1);

    void add_pending_query(const std::shared_ptr<query>& q);
    void remove_pending_query(const std::shared_ptr<query>& q);
    void send_pending_queries();

    bool is_authorized() const { return m_authorized; }
    void set_authorized(bool b = true) { m_authorized = b; }

    void set_logged_in(bool b = true) { m_logged_in = b; }

    bool is_configured() const { return m_configured; }
    void set_configured(bool b = true) { m_configured = b; }

    bool is_bound() const { return m_bound; }
    void set_bound(bool b = true) { m_bound = b; }

    int64_t logout_query_id() const { return m_logout_query_id; }
    void set_logout_query_id(int64_t id) { m_logout_query_id = id; }

    bool is_logging_out() const { return m_logout_query_id != 0; }

    void set_auth_key(const unsigned char* key, size_t length);

    void add_ipv6_option(const std::string& address, int port);
    void add_ipv4_option(const std::string& address, int port);

    bool auth_transfer_in_process() const { return m_auth_transfer_in_process; }
    void set_auth_transfer_in_process(bool b = true) { m_auth_transfer_in_process = b; }

    tgl_connection_status connection_status() const;

    void add_connection_status_observer(const std::weak_ptr<connection_status_observer>& observer);
    void remove_connection_status_observer(const std::weak_ptr<connection_status_observer>& observer);

    void transfer_auth_to_me();
    void configure();

private:
    void connected();
    void configured(bool success);
    void reset_temp_authorization();
    void cleanup_timer_expired();
    void send_all_acks();
    int64_t generate_next_msg_id();
    double get_server_time();
    void create_temp_auth_key();
    void restart_session();
    void rpc_send_packet(const char* data, size_t len);
    void send_req_pq_packet();
    void send_req_pq_temp_packet();
    int encrypt_inner_temp(const int32_t* msg, int msg_ints, void* data, int64_t msg_id);
    void send_req_dh_packet(TGLC_bn* pq, bool temp_key);
    void send_dh_params(TGLC_bn* dh_prime, TGLC_bn* g_a, int g, bool temp_key);
    void bind_temp_auth_key();
    void init_enc_msg(encrypted_message& enc_msg, bool useful);
    void init_enc_msg_inner_temp(encrypted_message& enc_msg, int64_t msg_id);
    void restart_authorization(bool temp_key);
    int rpc_execute_answer(tgl_in_buffer* in, int64_t msg_id, bool in_gzip = false);
    int work_container(tgl_in_buffer* in, int64_t msg_id);
    int work_new_session_created(tgl_in_buffer* in, int64_t msg_id);
    int work_packed(tgl_in_buffer* in, int64_t msg_id);
    int work_bad_server_salt(tgl_in_buffer* in);
    void insert_msg_id(int64_t id);
    void calculate_auth_key_id(bool temp_key);
    bool rpc_execute(int op, int len);
    bool process_respq_answer(const char* packet, int len, bool temp_key);
    bool process_dh_answer(const char* packet, int len, bool temp_key);
    bool process_auth_complete(const char* packet, int len, bool temp_key);
    bool process_rpc_message(encrypted_message* enc, int len);

private:
    int32_t m_id;
    state m_state;
    std::shared_ptr<tgl_session> m_session;
    std::array<unsigned char, 256> m_auth_key;
    std::array<unsigned char, 256> m_temp_auth_key;
    std::array<unsigned char, 16> m_nonce;
    std::array<unsigned char, 16> m_server_nonce;
    std::array<unsigned char, 32> m_new_nonce;
    int64_t m_auth_key_id;
    int64_t m_temp_auth_key_id;
    int64_t m_temp_auth_key_bind_query_id;
    int64_t m_server_salt;

    int64_t m_server_time_delta;
    double m_server_time_udelta;

    bool m_auth_transfer_in_process;

    std::vector<std::pair<std::string, int>> m_ipv6_options;
    std::vector<std::pair<std::string, int>> m_ipv4_options;

    size_t m_active_queries;
    int64_t m_logout_query_id;
    bool m_authorized;
    bool m_logged_in;
    bool m_configured;
    bool m_bound;
    std::list<std::shared_ptr<query>> m_pending_queries;

    std::shared_ptr<tgl_timer> m_session_cleanup_timer;
    std::shared_ptr<tgl_rsa_key> m_rsa_key;
    std::set<std::weak_ptr<connection_status_observer>, std::owner_less<std::weak_ptr<connection_status_observer>>> m_connection_status_observers;
};

#endif
