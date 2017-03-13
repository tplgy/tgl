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

#pragma once

#include "auto/auto.h"
#include "auto/auto-types.h"
#include "mtproto-common.h"
#include "mtproto_client.h"
#include "tgl/tgl_connection_status.h"
#include "tgl/tgl_peer_id.h"
#include "user_agent.h"

#include <memory>
#include <string>

class tgl_timer;

class query: public std::enable_shared_from_this<query>, public mtproto_client::connection_status_observer
{
public:
    enum class execution_option { UNKNOWN, NORMAL, LOGIN, LOGOUT, FORCE };

    query(const std::string& name, const paramed_type& type, int64_t msg_id_override = 0)
        : m_msg_id(0)
        , m_msg_id_override(msg_id_override)
        , m_session_id(0)
        , m_seq_no(0)
        , m_exec_option(execution_option::UNKNOWN)
        , m_connection_status(tgl_connection_status::disconnected)
        , m_ack_received(false)
        , m_name(name)
        , m_type(type)
        , m_serializer(std::make_shared<mtprotocol_serializer>())
        , m_timer()
        , m_client()
    {
    }

    ~query()
    {
        clear_timers();
    }

    void execute(const std::shared_ptr<mtproto_client>& client, execution_option = execution_option::NORMAL);
    bool execute_after_pending();
    void regen();
    void ack();
    void alarm();
    int handle_error(int error_code, const std::string& error_string);
    int handle_result(tgl_in_buffer* in);
    const std::shared_ptr<mtprotocol_serializer>& serializer() const { return m_serializer; }

    void out_i32s(const int32_t* ints, size_t num)
    {
        m_serializer->out_i32s(ints, num);
    }

    void out_i32(int32_t i)
    {
        m_serializer->out_i32(i);
    }

    void out_i64(int64_t i)
    {
        m_serializer->out_i64(i);
    }

    void out_double(double d)
    {
        m_serializer->out_double(d);
    }

    void out_string(const char* str, size_t size)
    {
        m_serializer->out_string(str, size);
    }

    void out_string(const char* str)
    {
        m_serializer->out_string(str);
    }

    void out_std_string(const std::string& str)
    {
        m_serializer->out_string(str.c_str(), str.size());
    }

    void out_random(int length)
    {
        m_serializer->out_random(length);
    }

    void out_peer_id(const user_agent* ua, const tgl_peer_id_t& id, int64_t access_hash);
    void out_input_peer(const user_agent* ua, const tgl_input_peer_t& id);

    void out_header(const user_agent* ua);

    const std::string& name() const { return m_name; }
    int64_t session_id() const { return m_session_id; }
    int64_t msg_id() const { return m_msg_id_override ? m_msg_id_override : m_msg_id; }
    const std::shared_ptr<mtproto_client>& client() const { return m_client; }

    virtual void on_answer(void* DS) = 0;
    virtual int on_error(int error_code, const std::string& error_string) = 0;
    virtual void on_timeout() { }
    virtual void on_connection_status_changed(tgl_connection_status status) { }

    virtual double timeout_interval() const { return m_ack_received ? 24.0 : 12.0; }
    virtual bool should_retry_on_timeout() const { return true; }
    virtual bool should_retry_after_recover_from_error() const { return true; }
    virtual bool is_file_transfer() const { return false; }

    virtual void will_be_pending() { }
    virtual void will_send() { }
    virtual void sent() { }

    bool ack_received() const { return m_ack_received; }
    void clear_timers();

protected:
    virtual bool handle_session_password_needed(bool& should_retry);
    void timeout_within(double seconds);
    void retry_within(double seconds);
    std::shared_ptr<user_agent> get_user_agent() const;

private:
    virtual void connection_status_changed(tgl_connection_status status) override final;
    bool is_force() const { return m_exec_option == execution_option::FORCE; }
    bool is_login() const { return m_exec_option == execution_option::LOGIN; }
    bool is_logout() const { return m_exec_option == execution_option::LOGOUT; }
    void timeout_alarm();
    bool check_logging_out();
    bool check_pending(bool transfer_auth = false);
    bool is_in_the_same_session() const;
    bool send();
    void on_answer_internal(void* DS);
    int on_error_internal(int error_code, const std::string& error_string);

private:
    int64_t m_msg_id;
    int64_t m_msg_id_override;
    int64_t m_session_id;
    int32_t m_seq_no;
    execution_option m_exec_option;
    tgl_connection_status m_connection_status;
    bool m_ack_received;
    const std::string m_name;
    paramed_type m_type;
    std::shared_ptr<mtprotocol_serializer> m_serializer;
    std::shared_ptr<tgl_timer> m_timer;
    std::shared_ptr<tgl_timer> m_retry_timer;
    std::shared_ptr<mtproto_client> m_client;
};
