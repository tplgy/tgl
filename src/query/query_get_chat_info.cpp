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

#include "query_get_chat_info.h"

#include "chat.h"
#include "tgl/tgl_update_callback.h"
#include "user.h"

namespace tgl {
namespace impl {

query_get_chat_info::query_get_chat_info(user_agent& ua, const std::function<void(bool)>& callback)
    : query(ua, "chat info", TYPE_TO_PARAM(messages_chat_full))
    , m_callback(callback)
{
}

void query_get_chat_info::on_answer(void* D)
{
    auto DS_MCF = static_cast<const tl_ds_messages_chat_full*>(D);

    if (!DS_MCF) {
        if (m_callback) {
            m_callback(false);
        }
        return;
    }

    if (DS_MCF->users) {
        for (int32_t i = 0; i < DS_LVAL(DS_MCF->users->cnt); i++) {
            if (auto u = user::create(DS_MCF->users->data[i])) {
                m_user_agent.user_fetched(u);
            }
        }
    }

    if (DS_MCF->chats) {
        for (int i = 0; i < DS_LVAL(DS_MCF->chats->cnt); i++) {
            if (auto c = chat::create(DS_MCF->chats->data[i])) {
                m_user_agent.chat_fetched(c);
            }
        }
    }

    const tl_ds_chat_full* DS_CF = DS_MCF->full_chat;

    if (DS_CF && DS_CF->magic == CODE_chat_full) {
        if (DS_CF->participants && DS_CF->participants->participants) {
            std::vector<std::shared_ptr<tgl_chat_participant>> participants;
            int32_t n = DS_LVAL(DS_CF->participants->participants->cnt);
            for (int32_t i = 0; i < n; ++i) {
                if (auto participant = create_chat_participant(DS_CF->participants->participants->data[i])) {
                    participants.push_back(participant);
                }
            }
            m_user_agent.callback()->chat_update_participants(DS_LVAL(DS_CF->id), participants);
        }
    }

    if (m_callback) {
        m_callback(true);
    }
}

int query_get_chat_info::on_error(int error_code, const std::string& error_string)
{
    TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
    if (m_callback) {
        m_callback(false);
    }
    return 0;
}

}
}
