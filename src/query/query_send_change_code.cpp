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

#include "login_context.h"
#include "query_send_code.h"
#include "query_set_phone.h"
#include "tgl/tgl_update_callback.h"

namespace tgl {
namespace impl {

query_send_change_code::query_send_change_code(user_agent& ua, const std::string& phone_number,
        const std::function<void(bool)>& callback)
    : query(ua, "send change phone code", TYPE_TO_PARAM(auth_sent_code))
    , m_callback(callback)
    , m_context(std::make_shared<login_context>(phone_number))
{
    out_header();
    out_i32(CODE_account_send_change_phone_code);
    out_std_string(phone_number);
}

void query_send_change_code::on_answer(void* D)
{
    set_phone_number_cb(std::make_unique<sent_code>(static_cast<const tl_ds_auth_sent_code*>(D)));
}

int query_send_change_code::on_error(int error_code, const std::string& error_string)
{
    TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
    set_phone_number_cb(nullptr);
    return 0;
}

void query_send_change_code::set_number_code(const std::string& code, tgl_login_action action)
{
    assert(m_context->sent_code);

    m_context->code = code;
    m_context->action = action;
    std::weak_ptr<query_send_change_code> weak_this(shared_from_this());
    auto q = std::make_shared<query_set_phone>(m_user_agent, [weak_this](bool success, const std::shared_ptr<tgl_user>& user) {
        auto shared_this = weak_this.lock();
        if (!shared_this) {
            return;
        }
        if (success) {
            if (shared_this->m_callback) {
                shared_this->m_callback(true);
            }
            return;
        }
        TGL_ERROR("incorrect code");
        shared_this->m_user_agent.callback()->get_value(std::make_shared<tgl_value_login_code>(
                [weak_this](const std::string& code, tgl_login_action action) {
                    if (auto shared_this = weak_this.lock()) {
                        shared_this->set_number_code(code, action);
                    }
                }, shared_this->m_context));
    });
    q->out_i32(CODE_account_change_phone);
    q->out_std_string(m_context->phone);
    q->out_std_string(m_context->sent_code->hash);
    q->out_std_string(m_context->code);
    q->execute(client());
}

void query_send_change_code::set_phone_number_cb(std::unique_ptr<struct sent_code>&& sent_code)
{
    if (!sent_code) {
        TGL_ERROR("incorrect phone number");
        if (m_callback) {
            m_callback(false);
        }
        return;
    }

    m_context->sent_code = std::move(sent_code);

    std::weak_ptr<query_send_change_code> weak_this(shared_from_this());
    m_user_agent.callback()->get_value(std::make_shared<tgl_value_login_code>(
            [weak_this](const std::string& code, tgl_login_action action) {
                if (auto shared_this = weak_this.lock()) {
                    shared_this->set_number_code(code, action);
                }
            }, m_context));
}

}
}
