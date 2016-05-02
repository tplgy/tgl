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
#include "types/query_methods.h"
#include "string.h"

#include <string>
#include <boost/variant.hpp>

static const float DEFAULT_QUERY_TIMEOUT = 6.0;

#define QUERY_ACK_RECEIVED 1
#define QUERY_FORCE_SEND 2
#define QUERY_LOGIN 4

class tgl_timer;

struct query {
    long long msg_id;
    int data_len;
    int flags;
    int seq_no;
    long long session_id;
    void *data;
    struct query_methods *methods;
    std::shared_ptr<tgl_timer> ev;
    std::shared_ptr<tgl_dc> DC;
    std::shared_ptr<tgl_session> session;
    struct paramed_type *type;
    std::shared_ptr<void> extra;
    std::shared_ptr<void> callback;
    virtual bool is_v2() const { return false; }
};

class query_v2: public query {
public:
    explicit query_v2(const std::string& name,
            const paramed_type& type_in)
        : m_name(name)
        , m_type(type_in)
    {
        msg_id = 0;
        data_len = 0;
        flags = 0;
        seq_no = 0;
        session_id = 0;
        methods = nullptr;
        type = &m_type;
    }

    void load_data(const void* data_in, int ints)
    {
        data_len = ints;
        data = talloc (4 * ints);
        memcpy(data, data_in, 4 * ints);
    }

    const std::string& name() const { return m_name; }

    virtual bool is_v2() const override { return true; }

    virtual void on_answer(void* DS) = 0;
    virtual int on_error(int error_code, const std::string& error_string) = 0;

    virtual double timeout_interval() const { return 0; }
    virtual void on_timeout() { };

private:
    const std::string m_name;
    paramed_type m_type;
};

void out_peer_id (tgl_peer_id_t id);

struct messages_send_extra {
  int multi = 0;
  tgl_message_id_t id;
  int count = 0;
  tgl_message_id_t *list = NULL;
};

std::shared_ptr<query> tglq_send_query (std::shared_ptr<tgl_dc> DC, int len, void *data, struct query_methods *methods, std::shared_ptr<void> extra, std::shared_ptr<void> callback);
void tglq_send_query_v2(const std::shared_ptr<tgl_dc>& DC, const std::shared_ptr<query_v2>& q, int flags = 0);

void tglq_query_ack (long long id);
int tglq_query_error (long long id);
int tglq_query_result (long long id);
void tglq_query_restart (long long id);

//double next_timer_in (void);
//void work_timers (void);

//extern struct query_methods help_get_config_methods;

double get_double_time (void);

struct send_file;
void send_file_encrypted_end (std::shared_ptr<send_file> f, std::shared_ptr<void> callback);

void tgl_do_send_bind_temp_key (std::shared_ptr<tgl_dc> D, long long nonce, int expires_at, void *data, int len, long long msg_id);

void tglq_regen_query (long long id);
void tglq_query_delete (long long id);
void tglq_query_free_all ();
void tglq_regen_queries_from_old_session (struct tgl_dc *DC, struct tgl_session *S);

// For binlog

//int get_dh_config_on_answer (struct query *q);
//void fetch_dc_option (void);
#endif
