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

#include "query_create_chat.h"

#include "updater.h"

namespace tgl {
namespace impl {

query_create_chat::query_create_chat(user_agent& ua, double timeout_seconds,
        const std::function<void(int32_t chat_id)>& callback, bool is_channel)
    : query_with_timeout(ua, is_channel ? "create channel" : "create chat", timeout_seconds, TYPE_TO_PARAM(updates))
    , m_callback(callback)
{
}

void query_create_chat::on_answer(void* D)
{
    tl_ds_updates* DS_U = static_cast<tl_ds_updates*>(D);

    m_user_agent.updater().work_any_updates(DS_U);

    int32_t chat_id = 0;
    if (DS_U->magic == CODE_updates && DS_U->chats && DS_U->chats->cnt && *DS_U->chats->cnt == 1) {
        chat_id = DS_LVAL(DS_U->chats->data[0]->id);
    }

    if (!chat_id) {
        assert(false);
    }

    if (m_callback) {
        m_callback(chat_id);
    }
}

int query_create_chat::on_error(int error_code, const std::string& error_string)
{
    TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
    if (m_callback) {
        m_callback(0);
    }
    return 0;
}

void query_create_chat::on_timeout()
{
    TGL_ERROR("timed out for query #" << msg_id() << " (" << name() << ")");
    if (m_callback) {
        m_callback(0);
    }
}

}
}
