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

#include "query_sign_in.h"

#include "query_user_info.h"

query_sign_in::query_sign_in(const std::function<void(bool, const std::shared_ptr<struct tgl_user>&)>& callback)
    : query("sign in", TYPE_TO_PARAM(auth_authorization))
    , m_callback(callback)
{ }

void query_sign_in::on_answer(void* D)
{
    TGL_DEBUG("sign_in_on_answer");
    tl_ds_auth_authorization* DS_AA = static_cast<tl_ds_auth_authorization*>(D);
    std::shared_ptr<struct tgl_user> user;
    if (auto ua = get_user_agent()) {
        user = tglf_fetch_alloc_user(ua.get(), DS_AA->user);
        ua->set_dc_logged_in(ua->active_client()->id());
    }
    if (m_callback) {
        m_callback(!!user, user);
    }
}

int query_sign_in::on_error(int error_code, const std::string& error_string)
{
    TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
    if (m_callback) {
        m_callback(false, nullptr);
    }
    return 0;
}

void query_sign_in::on_timeout()
{
    TGL_ERROR("timed out for query #" << msg_id() << " (" << name() << ")");
    if (m_callback) {
        m_callback(false, nullptr);
    }
}

double query_sign_in::timeout_interval() const
{
    return 20;
}

bool query_sign_in::should_retry_on_timeout() const
{
    return false;
}

void query_sign_in::will_be_pending()
{
    timeout_within(timeout_interval());
}

bool query_sign_in::handle_session_password_needed(bool& should_retry)
{
    should_retry = false;

    auto ua = get_user_agent();
    if (!ua) {
        return false;
    }

    assert(!ua->active_client()->is_logged_in());

    if (ua->is_password_locked()) {
        return true;
    }

    ua->set_password_locked(true);

    auto shared_this = shared_from_this();
    std::weak_ptr<user_agent> weak_ua = ua;
    ua->check_password([this, shared_this, weak_ua](bool success) {
        auto ua = weak_ua.lock();
        if (!ua || !success) {
            if (m_callback) {
                m_callback(false, nullptr);
            }
            return;
        }
        ua->set_dc_logged_in(ua->active_client()->id());
        auto q = std::make_shared<query_user_info>([this, shared_this](bool success, const std::shared_ptr<tgl_user>& user) {
            if (m_callback) {
                m_callback(success, user);
            }
        });
        q->out_i32(CODE_users_get_full_user);
        q->out_i32(CODE_input_user_self);
        q->execute(ua->active_client());
    });
    return true;
}
