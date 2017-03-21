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

#include "query_get_messages.h"

#include "chat.h"
#include "message.h"
#include "tgl/tgl_update_callback.h"
#include "user.h"

namespace tgl {
namespace impl {

query_get_messages::query_get_messages(user_agent& ua,
        const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& single_callback)
    : query(ua, "get messages (single)", TYPE_TO_PARAM(messages_messages))
    , m_single_callback(single_callback)
    , m_multi_callback(nullptr)
{ }

query_get_messages::query_get_messages(user_agent& ua,
        const std::function<void(bool, const std::vector<std::shared_ptr<tgl_message>>&)>& multi_callback)
    : query(ua, "get messages (multi)", TYPE_TO_PARAM(messages_messages))
    , m_single_callback(nullptr)
    , m_multi_callback(multi_callback)
{ }

void query_get_messages::on_answer(void* D)
{
    std::vector<std::shared_ptr<tgl_message>> messages;

    tl_ds_messages_messages* DS_MM = static_cast<tl_ds_messages_messages*>(D);
    int32_t n = DS_LVAL(DS_MM->users->cnt);
    for (int32_t i = 0; i < n; ++i) {
        if (auto u = user::create(DS_MM->users->data[i])) {
            m_user_agent.user_fetched(u);
        }
    }
    n = DS_LVAL(DS_MM->chats->cnt);
    for (int32_t i = 0; i < n; ++i) {
        if (auto c = chat::create(DS_MM->chats->data[i])) {
            m_user_agent.chat_fetched(c);
        }
    }

    n = DS_LVAL(DS_MM->messages->cnt);
    for (int32_t i = 0; i < n; ++i) {
        if (auto m = message::create(m_user_agent.our_id(), DS_MM->messages->data[i])) {
            messages.push_back(m);
        }
    }
    m_user_agent.callback()->new_messages(messages);
    if (m_multi_callback) {
        assert(!m_single_callback);
        m_multi_callback(true, messages);
    } else if (m_single_callback) {
        assert(!m_multi_callback);
        if (messages.size() > 0) {
            m_single_callback(true, messages[0]);
        } else {
            TGL_ERROR("no such message");
            m_single_callback(false, nullptr);
        }
    }
}

int query_get_messages::on_error(int error_code, const std::string& error_string)
{
    TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
    if (m_multi_callback) {
        assert(!m_single_callback);
        m_multi_callback(false, std::vector<std::shared_ptr<tgl_message>>());
    } else if (m_single_callback) {
        assert(!m_multi_callback);
        m_single_callback(false, nullptr);
    }
    return 0;
}

}
}
