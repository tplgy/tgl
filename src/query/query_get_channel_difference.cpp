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

#include "query_get_channel_difference.h"

#include "chat.h"
#include "message.h"
#include "tgl/tgl_update_callback.h"
#include "updater.h"
#include "user.h"

namespace tgl {
namespace impl {

query_get_channel_difference::query_get_channel_difference(user_agent& ua, const std::shared_ptr<channel>& c,
        const std::function<void(bool)>& callback)
    : query(ua, "get channel difference", TYPE_TO_PARAM(updates_channel_difference))
    , m_channel(c)
    , m_callback(callback)
{ }

void query_get_channel_difference::on_answer(void* D)
{
    tl_ds_updates_channel_difference* DS_UD = static_cast<tl_ds_updates_channel_difference*>(D);

    assert(m_channel->is_diff_locked());
    m_channel->set_diff_locked(false);

    if (DS_UD->magic == CODE_updates_channel_difference_empty) {
        TGL_DEBUG("empty difference, seq = " << m_user_agent.seq());
        if (m_callback) {
            m_callback(true);
        }
    } else {
        for (int32_t i = 0; i < DS_LVAL(DS_UD->users->cnt); i++) {
            if (auto u = user::create(DS_UD->users->data[i])) {
                m_user_agent.user_fetched(u);
            }
        }

        for (int32_t i = 0; i < DS_LVAL(DS_UD->chats->cnt); i++) {
            if (auto c = chat::create(DS_UD->chats->data[i])) {
                m_user_agent.chat_fetched(c);
            }
        }

        for (int32_t i = 0; i < DS_LVAL(DS_UD->other_updates->cnt); i++) {
            m_user_agent.updater().work_update(DS_UD->other_updates->data[i], update_mode::dont_check_and_update_consistency);
        }

        int message_count = DS_LVAL(DS_UD->new_messages->cnt);
        std::vector<std::shared_ptr<tgl_message>> messages;
        for (int32_t i = 0; i < message_count; i++) {
            if (auto m = message::create(m_user_agent.our_id(), DS_UD->new_messages->data[i])) {
                messages.push_back(m);
            }
        }
        m_user_agent.callback()->new_messages(messages);

        if (DS_UD->magic != CODE_updates_channel_difference_too_long) {
            if (m_callback) {
                m_callback(true);
            }
        } else {
            m_user_agent.get_channel_difference(m_channel->id(), m_callback);
        }
    }
}

int query_get_channel_difference::on_error(int error_code, const std::string& error_string)
{
    TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
    if (m_callback) {
        m_callback(false);
    }
    return 0;
}

}
}
