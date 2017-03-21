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

#include "query_search_message.h"

#include "chat.h"
#include "message.h"
#include "tgl/tgl_update_callback.h"
#include "user.h"

namespace tgl {
namespace impl {

query_search_message::query_search_message(user_agent& ua,
        const std::shared_ptr<message_search_state>& state,
        const std::function<void(bool, const std::vector<std::shared_ptr<tgl_message>>&)>& callback)
    : query(ua, "messages search", TYPE_TO_PARAM(messages_messages))
    , m_state(state)
    , m_callback(callback)
{
    assemble();
}

void query_search_message::on_answer(void* D)
{
    const tl_ds_messages_messages* DS_MM = static_cast<const tl_ds_messages_messages*>(D);
    int32_t n = DS_LVAL(DS_MM->chats->cnt);
    for (int32_t i = 0; i < n; ++i) {
        if (auto c = chat::create(DS_MM->chats->data[i])) {
            m_user_agent.chat_fetched(c);
        }
    }
    n = DS_LVAL(DS_MM->users->cnt);
    for (int32_t i = 0; i < n; ++i) {
        if (auto u = user::create(DS_MM->users->data[i])) {
            m_user_agent.user_fetched(u);
        }
    }

    n = DS_LVAL(DS_MM->messages->cnt);
    for (int32_t i = 0; i < n; ++i) {
        if (auto m = message::create(m_user_agent.our_id(), DS_MM->messages->data[i])) {
            m_state->messages.push_back(m);
        }
    }
    m_user_agent.callback()->new_messages(m_state->messages);
    m_state->offset += n;
    m_state->limit -= n;
    if (m_state->limit + m_state->offset >= DS_LVAL(DS_MM->count)) {
        m_state->limit = DS_LVAL(DS_MM->count) - m_state->offset;
        if (m_state->limit < 0) {
            m_state->limit = 0;
        }
    }
    assert(m_state->limit >= 0);

    if (m_state->limit <= 0 || DS_MM->magic == CODE_messages_messages) {
        if (m_callback) {
            m_callback(true, m_state->messages);
        }
    } else {
        m_state->max_id = m_state->messages[m_state->messages.size()-1]->id();
        m_state->offset = 0;
        search_more();
    }
}

int query_search_message::on_error(int error_code, const std::string& error_string)
{
    TGL_ERROR("RPC_CALL_FAIL " <<  error_code << " " << error_string);
    if (m_callback) {
        m_callback(0, std::vector<std::shared_ptr<tgl_message>>());
    }
    return 0;
}

void query_search_message::assemble()
{
    if (m_state->id.peer_type == tgl_peer_type::unknown) {
        out_i32(CODE_messages_search_global);
        out_std_string(m_state->query);
        out_i32(0);
        out_i32(CODE_input_peer_empty);
        out_i32(m_state->offset);
        out_i32(m_state->limit);
    } else {
        out_i32(CODE_messages_search);
        out_i32(0);
        out_input_peer(m_state->id);
        out_std_string(m_state->query);
        out_i32(CODE_input_messages_filter_empty);
        out_i32(m_state->from);
        out_i32(m_state->to);
        out_i32(m_state->offset); // offset
        out_i32(m_state->max_id); // max_id
        out_i32(m_state->limit);
    }
}

void query_search_message::search_more()
{
    auto q = std::make_shared<query_search_message>(m_user_agent, m_state, m_callback);
    q->execute(client());
}

}
}
