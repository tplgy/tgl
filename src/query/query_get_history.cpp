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

#include "query_get_history.h"

#include "chat.h"
#include "structures.h"
#include "tgl/tgl_update_callback.h"
#include "user.h"

namespace tgl {
namespace impl {

query_get_history::query_get_history(const tgl_input_peer_t& id, int limit, int offset, int max_id,
        const std::function<void(bool, const std::vector<std::shared_ptr<tgl_message>>&)>& callback)
    : query("get history", TYPE_TO_PARAM(messages_messages))
    , m_id(id)
#if 0
    , m_limit(limit)
    , m_offset(offset)
    , m_max_id(max_id)
#endif
    , m_callback(callback)
{ }

void query_get_history::on_answer(void* D)
{
    TGL_DEBUG("get history on answer for query #" << msg_id());
    tl_ds_messages_messages* DS_MM = static_cast<tl_ds_messages_messages*>(D);

    if (auto ua = get_user_agent()) {
        int32_t n = DS_LVAL(DS_MM->chats->cnt);
        for (int32_t i = 0; i < n; i++) {
            ua->chat_fetched(chat::create(DS_MM->chats->data[i]));
        }
        n = DS_LVAL(DS_MM->users->cnt);
        for (int32_t i = 0; i < n; i++) {
            ua->user_fetched(std::make_shared<user>(DS_MM->users->data[i]));
        }
        n = DS_LVAL(DS_MM->messages->cnt);
        for (int32_t i = 0; i < n; i++) {
            auto message = tglf_fetch_alloc_message(ua.get(), DS_MM->messages->data[i]);
            message->set_history(true);
            m_messages.push_back(message);
        }
        ua->callback()->new_messages(m_messages);
    }

#if 0
    m_offset += n;
    m_limit -= n;

    int count = DS_LVAL(DS_MM->count);
    if (count >= 0 && m_limit + m_offset >= count) {
        m_limit = count - m_offset;
        if (m_limit < 0) {
            m_limit = 0;
        }
    }
    assert(m_limit >= 0);
#endif

    if (m_callback) {
        m_callback(true, m_messages);
    }

#if 0
    if (m_limit <= 0 || DS_MM->magic == CODE_messages_messages || DS_MM->magic == CODE_messages_channel_messages) {

        /*if (m_messages.size() > 0) {
          tgl_do_messages_mark_read(m_id, m_messages[0]->id, 0, 0, 0);
        }*/
    } else {
        /*m_offset = 0;
        m_max_id = m_messages[m_messages.size()-1]->permanent_id.id;
        _tgl_do_get_history(m_id, m_offset, m_limit, m_max_id,
                m_callback);*/
    }
#endif
}

int query_get_history::on_error(int error_code, const std::string& error_string)
{
    TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
    if (m_callback) {
        m_callback(false, std::vector<std::shared_ptr<tgl_message>>());
    }
    return 0;
}

}
}
