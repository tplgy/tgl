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

query_search_message::query_search_message(const std::shared_ptr<msg_search_state>& state,
        const std::function<void(bool, const std::vector<std::shared_ptr<tgl_message>>&)>& callback)
    : query("messages search", TYPE_TO_PARAM(messages_messages))
    , m_state(state)
    , m_callback(callback)
{ }

void query_search_message::on_answer(void* D)
{
    auto ua = get_user_agent();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        if (m_callback) {
            m_callback(0, std::vector<std::shared_ptr<tgl_message>>());
        }
        return;
    }

    tl_ds_messages_messages* DS_MM = static_cast<tl_ds_messages_messages*>(D);
    int32_t n = DS_LVAL(DS_MM->chats->cnt);
    for (int32_t i = 0; i < n; ++i) {
        if (auto c = chat::create(DS_MM->chats->data[i])) {
            ua->chat_fetched(c);
        }
    }
    n = DS_LVAL(DS_MM->users->cnt);
    for (int32_t i = 0; i < n; ++i) {
        if (auto u = user::create(DS_MM->users->data[i])) {
            ua->user_fetched(u);
        }
    }

    n = DS_LVAL(DS_MM->messages->cnt);
    for (int32_t i = 0; i < n; ++i) {
        if (auto m = message::create(ua->our_id(), DS_MM->messages->data[i])) {
            m_state->messages.push_back(m);
        }
    }
    ua->callback()->new_messages(m_state->messages);
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
        tgl_do_msg_search(m_state, m_callback);
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

void tgl_do_msg_search(const std::shared_ptr<msg_search_state>& state,
        const std::function<void(bool, const std::vector<std::shared_ptr<tgl_message>>&)>& callback)
{
    auto ua = state->weak_user_agent.lock();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        if (callback) {
            callback(false, {});
        }
        return;
    }

    auto q = std::make_shared<query_search_message>(state, callback);
    if (state->id.peer_type == tgl_peer_type::unknown) {
        q->out_i32(CODE_messages_search_global);
        q->out_std_string(state->query);
        q->out_i32(0);
        q->out_i32(CODE_input_peer_empty);
        q->out_i32(state->offset);
        q->out_i32(state->limit);
    } else {
        q->out_i32(CODE_messages_search);
        q->out_i32(0);
        q->out_input_peer(ua.get(), state->id);
        q->out_std_string(state->query);
        q->out_i32(CODE_input_messages_filter_empty);
        q->out_i32(state->from);
        q->out_i32(state->to);
        q->out_i32(state->offset); // offset
        q->out_i32(state->max_id); // max_id
        q->out_i32(state->limit);
    }
    q->execute(ua->active_client());
}

}
}
