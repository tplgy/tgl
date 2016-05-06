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
#include "auto.h"
#include "tgl-layout.h"
#include "types/tgl_message.h"
#include "tgl-dc.h"
#include "string.h"

#include <memory>
#include <string>
#include <boost/variant.hpp>
#include <vector>

static const float DEFAULT_QUERY_TIMEOUT = 6.0;

#define QUERY_ACK_RECEIVED 1
#define QUERY_FORCE_SEND 2
#define QUERY_LOGIN 4

class tgl_timer;

class query: public std::enable_shared_from_this<query>
{
public:
    query(const std::string& name, const paramed_type& type)
        : m_name(name)
        , m_type(type)
        , m_data()
        , m_flags(0)
        , m_seq_no(0)
        , m_msg_id(0)
        , m_session_id(0)
        , m_timer()
        , m_dc()
        , m_session()
    {
    }

    ~query()
    {
        clear_timer();
    }

    void execute(const std::shared_ptr<tgl_dc>& dc, int flags = 0);
    bool execute_after_pending();
    void alarm();
    void regen();
    void ack();
    void cancel_timer();
    void clear_timer();
    int handle_error(int error_code, const std::string& error_string);
    void handle_result();

    void load_data(const void* data_in, int ints)
    {
        static_assert(sizeof(int) == 4, "We assume int is 4 bytes");
        m_data.resize(4 * ints);
        memcpy(m_data.data(), data_in, m_data.size());
    }

    paramed_type* type() { return &m_type; }
    const std::string& name() const { return m_name; }
    long long session_id() const { return m_session_id; }
    long long msg_id() const { return m_msg_id; }
    int flags() const { return m_flags; }
    const std::shared_ptr<tgl_session>& session() const { return m_session; }
    const std::shared_ptr<tgl_dc>& dc() const { return m_dc; }

    virtual void on_answer(void* DS) = 0;
    virtual int on_error(int error_code, const std::string& error_string) = 0;

    virtual double timeout_interval() const { return 0; }
    virtual bool on_timeout() { return false; };

private:
    const std::string m_name;
    paramed_type m_type;
    std::vector<char> m_data;
    int m_flags;
    int m_seq_no;
    long long m_msg_id;
    long long m_session_id;
    std::shared_ptr<tgl_timer> m_timer;
    std::shared_ptr<tgl_dc> m_dc;
    std::shared_ptr<tgl_session> m_session;
};

void out_peer_id (tgl_peer_id_t id);

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
            const std::function<void(bool, const std::shared_ptr<tgl_message>&)> single_callback);
    query_send_msgs(const std::shared_ptr<messages_send_extra>& extra,
            const std::function<void(bool success, const std::vector<std::shared_ptr<tgl_message>>& messages)>& multi_callback);
    explicit query_send_msgs(const std::function<void(bool)>& bool_callback);
    virtual void on_answer(void *D) override;
    virtual int on_error(int error_code, const std::string& error_string) override;

private:
    std::shared_ptr<messages_send_extra> m_extra;
    std::function<void(bool, const std::shared_ptr<tgl_message>&)> m_single_callback;
    std::function<void(bool, const std::vector<std::shared_ptr<tgl_message>>& messages)> m_multi_callback;
    std::function<void(bool)> m_bool_callback;
};

void tglq_query_ack (long long id);
int tglq_query_error (long long id);
int tglq_query_result (long long id);
void tglq_query_restart (long long id);

//double next_timer_in (void);
//void work_timers (void);

double get_double_time (void);

struct send_file;
void send_file_encrypted_end(std::shared_ptr<send_file> f, const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback);

void tgl_do_send_bind_temp_key (std::shared_ptr<tgl_dc> D, long long nonce, int expires_at, void *data, int len, long long msg_id);

void tglq_regen_query (long long id);
void tglq_query_delete (long long id);
void tglq_regen_queries_from_old_session (struct tgl_dc *DC, struct tgl_session *S);

#endif
