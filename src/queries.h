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

#ifndef __QUERIES_H__
#define __QUERIES_H__

#include "mtproto-common.h"
#include "query.h"
#include "structures.h"
#include "tgl/tgl_message.h"

#include <cstdint>
#include <exception>
#include <memory>
#include <string>
#include <string.h>
#include <vector>

struct messages_send_extra {
    bool multi = false;
    int64_t id = 0;
    int count = 0;
    std::vector<int64_t> message_ids;
};

class query_send_msgs: public query
{
public:
    query_send_msgs(const std::shared_ptr<messages_send_extra>& extra,
            const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& single_callback);
    query_send_msgs(const std::shared_ptr<messages_send_extra>& extra,
            const std::function<void(bool success, const std::vector<std::shared_ptr<tgl_message>>& messages)>& multi_callback);
    explicit query_send_msgs(const std::function<void(bool)>& bool_callback);
    virtual void on_answer(void* D) override;
    virtual int on_error(int error_code, const std::string& error_string) override;
    void set_message(const std::shared_ptr<tgl_message>& message);

private:
    std::shared_ptr<messages_send_extra> m_extra;
    std::function<void(bool, const std::shared_ptr<tgl_message>&)> m_single_callback;
    std::function<void(bool, const std::vector<std::shared_ptr<tgl_message>>& messages)> m_multi_callback;
    std::function<void(bool)> m_bool_callback;
    std::shared_ptr<tgl_message> m_message;
};

void tglq_query_ack(int64_t id);
int tglq_query_error(tgl_in_buffer* in, int64_t id);
int tglq_query_result(tgl_in_buffer* in, int64_t id);
void tglq_query_restart(int64_t id);

double get_double_time(void);

void tgl_do_bind_temp_key(const std::shared_ptr<mtproto_client>& client, int64_t nonce, int32_t expires_at, void* data, int len, int64_t msg_id);
void tgl_do_get_channel_difference(const tgl_input_peer_t& channel_id, const std::function<void(bool success)>& callback);
void tgl_do_lookup_state();
void tgl_do_help_get_client_config(const std::shared_ptr<mtproto_client>& client);
void tgl_do_set_client_configured(const std::shared_ptr<mtproto_client>& client, bool success);
void tgl_do_set_client_logged_out(const std::shared_ptr<mtproto_client>& client, bool success);
void tgl_do_check_password(const std::function<void(bool success)>& callback);

void tglq_regen_query(int64_t id);
void tglq_query_delete(int64_t id);

void fetch_dc_option(const tl_ds_dc_option* DS_DO);

#endif
