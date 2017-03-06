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

#include "query_send_change_code.h"

#include "query_set_phone.h"
#include "tgl/tgl_update_callback.h"

query_send_change_code::query_send_change_code(const std::function<void(bool, const std::string&)>& callback)
    : query("send change phone code", TYPE_TO_PARAM(account_sent_change_phone_code))
    , m_callback(callback)
{ }

void query_send_change_code::on_answer(void* D)
{
    tl_ds_account_sent_change_phone_code* DS_ASCPC = static_cast<tl_ds_account_sent_change_phone_code*>(D);
    std::string phone_code_hash;
    if (DS_ASCPC->phone_code_hash && DS_ASCPC->phone_code_hash->data) {
        phone_code_hash = std::string(DS_ASCPC->phone_code_hash->data, DS_ASCPC->phone_code_hash->len);
    }
    if (m_callback) {
        m_callback(true, phone_code_hash);
    }
}

int query_send_change_code::on_error(int error_code, const std::string& error_string)
{
    TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
    if (m_callback) {
        m_callback(false, std::string());
    }
    return 0;
}

static void tgl_set_number_code(const std::shared_ptr<change_phone_state>& state, const std::string& code, tgl_login_action action);

static void tgl_set_number_result(const std::shared_ptr<change_phone_state>& state, bool success, const std::shared_ptr<tgl_user>&)
{
    if (success) {
        if (state->callback) {
            state->callback(true);
        }
    } else {
        TGL_ERROR("incorrect code");
        auto ua = state->weak_user_agent.lock();
        if (!ua) {
            TGL_ERROR("the user agent has gone");
            return;
        }
        ua->callback()->get_value(std::make_shared<tgl_value_login_code>(
                std::bind(tgl_set_number_code, state, std::placeholders::_1, std::placeholders::_2)));
    }
}

static void tgl_set_number_code(const std::shared_ptr<change_phone_state>& state, const std::string& code, tgl_login_action action)
{
    auto ua = state->weak_user_agent.lock();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        return;
    }

    auto q = std::make_shared<query_set_phone>(std::bind(tgl_set_number_result, state, std::placeholders::_1, std::placeholders::_2));
    q->out_i32(CODE_account_change_phone);
    q->out_std_string(state->phone);
    q->out_std_string(state->hash);
    q->out_std_string(code);
    q->execute(ua->active_client());
}

void tgl_set_phone_number_cb(const std::shared_ptr<change_phone_state>& state, bool success, const std::string& hash)
{
    if (!success) {
        TGL_ERROR("incorrect phone number");
        if (state->callback) {
            state->callback(false);
        }
        return;
    }

    auto ua = state->weak_user_agent.lock();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        return;
    }

    state->hash = hash;
    ua->callback()->get_value(std::make_shared<tgl_value_login_code>(
            std::bind(tgl_set_number_code, state, std::placeholders::_1, std::placeholders::_2)));
}
