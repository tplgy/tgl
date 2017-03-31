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

#include "query_get_difference.h"

#include "chat.h"
#include "message.h"
#include "tgl/tgl_update_callback.h"
#include "updater.h"
#include "user.h"

namespace tgl {
namespace impl {

query_get_difference::query_get_difference(user_agent& ua, const std::function<void(bool)>& callback)
    : query(ua, "get difference", TYPE_TO_PARAM(updates_difference))
    , m_callback(callback)
{ }

void query_get_difference::on_answer(void* D)
{
    TGL_DEBUG("get difference answer");

    const tl_ds_updates_difference* DS_UD = static_cast<const tl_ds_updates_difference*>(D);

    assert(m_user_agent.is_diff_locked());
    m_user_agent.set_diff_locked(false);

    if (DS_UD->magic == CODE_updates_difference_empty) {
        m_user_agent.set_date(DS_LVAL(DS_UD->date));
        m_user_agent.set_seq(DS_LVAL(DS_UD->seq));
        TGL_DEBUG("empty difference, seq = " << m_user_agent.seq());
        if (m_callback) {
            m_callback(true);
        }
    } else {
        int32_t n = DS_LVAL(DS_UD->users->cnt);
        for (int32_t i = 0; i < n; ++i) {
            if (auto u = user::create(DS_UD->users->data[i])) {
                m_user_agent.user_fetched(u);
            }
        }

        n = DS_LVAL(DS_UD->chats->cnt);
        for (int32_t i = 0; i < n; ++i) {
            if (auto c = chat::create(DS_UD->chats->data[i])) {
                m_user_agent.chat_fetched(c);
            }
        }

        n = DS_LVAL(DS_UD->other_updates->cnt);
        for (int32_t i = 0; i < n; ++i) {
            m_user_agent.updater().work_update(DS_UD->other_updates->data[i], update_mode::dont_check_and_update_consistency);
        }

        int32_t message_count = DS_LVAL(DS_UD->new_messages->cnt);
        std::vector<std::shared_ptr<tgl_message>> messages;
        for (int32_t i = 0; i < message_count; ++i) {
            if (auto m = message::create(m_user_agent.our_id(), DS_UD->new_messages->data[i])) {
                messages.push_back(m);
            }
        }
        m_user_agent.callback()->new_messages(messages);
        messages.clear();

        int32_t encrypted_message_count = DS_LVAL(DS_UD->new_encrypted_messages->cnt);
        for (int32_t i = 0; i < encrypted_message_count; ++i) {
            m_user_agent.updater().work_encrypted_message(DS_UD->new_encrypted_messages->data[i]);
        }

        if (DS_UD->state) {
            m_user_agent.set_pts(DS_LVAL(DS_UD->state->pts));
            m_user_agent.set_qts(DS_LVAL(DS_UD->state->qts));
            m_user_agent.set_date(DS_LVAL(DS_UD->state->date));
            m_user_agent.set_seq(DS_LVAL(DS_UD->state->seq));
        } else {
            m_user_agent.set_pts(DS_LVAL(DS_UD->intermediate_state->pts));
            m_user_agent.set_qts(DS_LVAL(DS_UD->intermediate_state->qts));
            m_user_agent.set_date(DS_LVAL(DS_UD->intermediate_state->date));
            m_user_agent.get_difference(false, m_callback);
            return;
        }

        if (m_callback) {
            m_callback(true);
        }
    }
}

int query_get_difference::on_error(int error_code, const std::string& error_string)
{
    TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
    if (m_callback) {
        m_callback(false);
    }
    return 0;
}

}
}
