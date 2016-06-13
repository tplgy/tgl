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
//#include "net.h"
#ifndef __QUERIES_H__
#define __QUERIES_H__
#include "tgl-structures.h"
#include "auto/auto.h"
#include "tgl-layout.h"
#include "types/tgl_message.h"
#include "tgl-dc.h"
#include "mtproto-common.h"

#include <string.h>
#include <cstdint>
#include <exception>
#include <memory>
#include <string>
#include <vector>

static const float DEFAULT_QUERY_TIMEOUT = 6.0;

class tgl_timer;

class query: public std::enable_shared_from_this<query>
{
public:
    enum class execution_option { UNKNOWN, NORMAL, LOGIN, FORCE };

    query(const std::string& name, const paramed_type& type, long long msg_id_override = 0)
        : m_msg_id(0)
        , m_msg_id_override(msg_id_override)
        , m_session_id(0)
        , m_seq_no(0)
        , m_exec_option(execution_option::UNKNOWN)
        , m_ack_received(false)
        , m_name(name)
        , m_type(type)
        , m_serializer(std::make_shared<mtprotocol_serializer>())
        , m_timer()
        , m_dc()
        , m_session()
    {
    }

    ~query()
    {
        clear_timer();
    }

    void execute(const std::shared_ptr<tgl_dc>& dc, execution_option = execution_option::NORMAL);
    bool execute_after_pending();
    void alarm();
    void regen();
    void ack();
    void cancel_timer();
    void clear_timer();
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

    void out_peer_id(const tgl_peer_id_t& id);

    void out_header();

    const std::string& name() const { return m_name; }
    long long session_id() const { return m_session_id; }
    long long msg_id() const { return m_msg_id; }
    const std::shared_ptr<tgl_session>& session() const { return m_session; }
    const std::shared_ptr<tgl_dc>& dc() const { return m_dc; }

    virtual void on_answer(void* DS) = 0;
    virtual int on_error(int error_code, const std::string& error_string) = 0;

    virtual double timeout_interval() const { return 0; }
    virtual bool on_timeout() { return false; };

private:
    bool is_force() const { return m_exec_option == execution_option::FORCE; }
    bool is_login() const { return m_exec_option == execution_option::LOGIN; }

private:
    long long m_msg_id;
    long long m_msg_id_override;
    long long m_session_id;
    int m_seq_no;
    execution_option m_exec_option;
    bool m_ack_received;
    const std::string m_name;
    paramed_type m_type;
    std::shared_ptr<mtprotocol_serializer> m_serializer;
    std::shared_ptr<tgl_timer> m_timer;
    std::shared_ptr<tgl_dc> m_dc;
    std::shared_ptr<tgl_session> m_session;
};

struct messages_send_extra {
  bool multi = false;
  tgl_message_id_t id;
  int count = 0;
  std::vector<tgl_message_id_t> message_ids;
};

class query_send_msgs: public query
{
public:
    query_send_msgs(const std::shared_ptr<messages_send_extra>& extra,
            const std::function<void(bool, const std::shared_ptr<tgl_message>&, float)> single_callback);
    query_send_msgs(const std::shared_ptr<messages_send_extra>& extra,
            const std::function<void(bool success, const std::vector<std::shared_ptr<tgl_message>>& messages)>& multi_callback);
    explicit query_send_msgs(const std::function<void(bool)>& bool_callback);
    virtual void on_answer(void *D) override;
    virtual int on_error(int error_code, const std::string& error_string) override;
    void set_message(const std::shared_ptr<tgl_message>& message);

private:
    std::shared_ptr<messages_send_extra> m_extra;
    std::function<void(bool, const std::shared_ptr<tgl_message>&, float)> m_single_callback;
    std::function<void(bool, const std::vector<std::shared_ptr<tgl_message>>& messages)> m_multi_callback;
    std::function<void(bool)> m_bool_callback;
    std::shared_ptr<tgl_message> m_message;
};

void tglq_query_ack (long long id);
int tglq_query_error (tgl_in_buffer* in, long long id);
int tglq_query_result (tgl_in_buffer* in, long long id);
void tglq_query_restart (long long id);

//double next_timer_in (void);
//void work_timers (void);

double get_double_time (void);

struct send_file;
void send_file_encrypted_end(std::shared_ptr<send_file> f, const std::function<void(bool, const std::shared_ptr<tgl_message>&, float)>& callback);

void tgl_do_send_bind_temp_key (std::shared_ptr<tgl_dc> D, long long nonce, int expires_at, void *data, int len, long long msg_id);

void tglq_regen_query (long long id);
void tglq_query_delete (long long id);
void tglq_regen_queries_from_old_session (struct tgl_dc *DC, struct tgl_session *S);

#endif
