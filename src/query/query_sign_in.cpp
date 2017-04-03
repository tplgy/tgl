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
#include "user.h"

namespace tgl {
namespace impl {

query_sign_in::query_sign_in(user_agent& ua, double timeout_seconds,
        const std::function<void(bool, const std::shared_ptr<user>&)>& callback)
    : query_with_timeout(ua, "sign in", timeout_seconds, TYPE_TO_PARAM(auth_authorization))
    , m_callback(callback)
{ }

void query_sign_in::on_answer(void* D)
{
    TGL_DEBUG("sign_in_on_answer");
    tl_ds_auth_authorization* DS_AA = static_cast<tl_ds_auth_authorization*>(D);
    std::shared_ptr<user> u = user::create(DS_AA->user);
    if (u) {
        m_user_agent.user_fetched(u);
    }
    m_user_agent.set_dc_logged_in(m_user_agent.active_client()->id());
    if (m_callback) {
        m_callback(!!u, u);
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

bool query_sign_in::handle_session_password_needed(bool& should_retry)
{
    should_retry = false;

    assert(!m_user_agent.active_client()->is_logged_in());

    if (m_user_agent.is_password_locked()) {
        return true;
    }

    m_user_agent.set_password_locked(true);

    // handle_session_password_needed is called in error
    // handling code in the super class. As a result
    // the query has been popped off from the user_agent.
    // We need to add it into the user_agent again to keep
    // it going.
    m_user_agent.add_active_query(shared_from_this());

    std::weak_ptr<query_sign_in> weak_this(shared_from_this());
    m_user_agent.check_password([this, weak_this](bool success) {
        auto shared_this = weak_this.lock();
        if (!shared_this || !success) {
            if (shared_this) {
                m_user_agent.remove_active_query(shared_this);
                if (m_callback) {
                    m_callback(false, nullptr);
                }
            }
            return;
        }
        m_user_agent.set_dc_logged_in(m_user_agent.active_client()->id());
        auto q = std::make_shared<query_user_info>(m_user_agent, [this, weak_this](bool success, const std::shared_ptr<user>& u) {
            auto shared_this = weak_this.lock();
            if (!shared_this) {
                return;
            }
            m_user_agent.remove_active_query(shared_this);

            if (m_callback) {
                m_callback(success, u);
            }
        });
        q->out_i32(CODE_users_get_full_user);
        q->out_i32(CODE_input_user_self);
        q->execute(m_user_agent.active_client());
    });
    return true;
}

}
}
