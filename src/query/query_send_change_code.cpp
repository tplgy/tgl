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

namespace tgl {
namespace impl {

struct change_phone_state {
    std::string phone;
    std::string hash;
    std::string first_name;
    std::string last_name;
};

query_send_change_code::query_send_change_code(user_agent& ua, const std::string& phone_number,
        const std::function<void(bool)>& callback)
    : query(ua, "send change phone code", TYPE_TO_PARAM(account_sent_change_phone_code))
    , m_callback(callback)
    , m_state(std::make_shared<change_phone_state>())
{
    m_state->phone = phone_number;
    out_header();
    out_i32(CODE_account_send_change_phone_code);
    out_std_string(phone_number);
}

void query_send_change_code::on_answer(void* D)
{
    tl_ds_account_sent_change_phone_code* DS_ASCPC = static_cast<tl_ds_account_sent_change_phone_code*>(D);
    std::string phone_code_hash;
    if (DS_ASCPC->phone_code_hash && DS_ASCPC->phone_code_hash->data) {
        phone_code_hash = std::string(DS_ASCPC->phone_code_hash->data, DS_ASCPC->phone_code_hash->len);
    }
    set_phone_number_cb(true, phone_code_hash);
}

int query_send_change_code::on_error(int error_code, const std::string& error_string)
{
    TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
    set_phone_number_cb(false, std::string());
    return 0;
}

void query_send_change_code::set_number_result(bool success, const std::shared_ptr<tgl_user>&)
{
    if (success) {
        if (m_callback) {
            m_callback(true);
        }
    } else {
        TGL_ERROR("incorrect code");
        std::weak_ptr<query_send_change_code> weak_this(shared_from_this());
        m_user_agent.callback()->get_value(std::make_shared<tgl_value_login_code>(
                [weak_this](const std::string& code, tgl_login_action action) {
                    if (auto shared_this = weak_this.lock()) {
                        shared_this->set_number_code(code, action);
                    }
                }));
    }
}

void query_send_change_code::set_number_code(const std::string& code, tgl_login_action action)
{
    std::weak_ptr<query_send_change_code> weak_this(shared_from_this());
    auto q = std::make_shared<query_set_phone>(m_user_agent,
            [weak_this](bool success, const std::shared_ptr<tgl_user>& user) {
                if (auto shared_this = weak_this.lock()) {
                    shared_this->set_number_result(success, user);
                }
            });
    q->out_i32(CODE_account_change_phone);
    q->out_std_string(m_state->phone);
    q->out_std_string(m_state->hash);
    q->out_std_string(code);
    q->execute(client());
}

void query_send_change_code::set_phone_number_cb(bool success, const std::string& hash)
{
    if (!success) {
        TGL_ERROR("incorrect phone number");
        if (m_callback) {
            m_callback(false);
        }
        return;
    }

    m_state->hash = hash;

    std::weak_ptr<query_send_change_code> weak_this(shared_from_this());
    m_user_agent.callback()->get_value(std::make_shared<tgl_value_login_code>(
            [weak_this](const std::string& code, tgl_login_action action) {
                if (auto shared_this = weak_this.lock()) {
                    shared_this->set_number_code(code, action);
                }
            }));
}

}
}
