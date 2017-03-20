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

#include "query_messages_request_encryption.h"

#include "auto/auto.h"
#include "secret_chat.h"
#include "tgl/tgl_update_callback.h"

namespace tgl {
namespace impl {

query_messages_request_encryption::query_messages_request_encryption(
        const std::shared_ptr<secret_chat>& sc,
        const std::function<void(bool, const std::shared_ptr<secret_chat>&)>& callback)
    : query("send encrypted (chat request)", TYPE_TO_PARAM(encrypted_chat))
    , m_secret_chat(sc)
    , m_callback(callback)
{ }

void query_messages_request_encryption::on_answer(void* D)
{
    auto ua = get_user_agent();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        if (m_callback) {
            m_callback(false, nullptr);
        }
        return;
    }

    std::shared_ptr<secret_chat> sc = ua->allocate_or_update_secret_chat(static_cast<tl_ds_encrypted_chat*>(D));

    if (!sc) {
        if (m_callback) {
            m_callback(false, sc);
        }
        return;
    }

    ua->callback()->secret_chat_update(sc);

    if (m_callback) {
        m_callback(sc->state() != tgl_secret_chat_state::deleted, sc);
    }
}

int query_messages_request_encryption::on_error(int error_code, const std::string& error_string)
{
    TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
    if (m_callback) {
        m_callback(false, m_secret_chat);
    }

    return 0;
}

void query_messages_request_encryption::on_timeout()
{
    TGL_ERROR("timed out for query #" << msg_id() << " (" << name() << ")");
    if (m_callback) {
        m_callback(false, m_secret_chat);
    }
}

double query_messages_request_encryption::timeout_interval() const
{
    return 10;
}

bool query_messages_request_encryption::should_retry_on_timeout() const
{
    return false;
}

void query_messages_request_encryption::will_be_pending()
{
    timeout_within(timeout_interval());
}

}
}
