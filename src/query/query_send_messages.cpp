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

#include "query_send_messages.h"

#include "updater.h"

namespace tgl {
namespace impl {

query_send_messages::query_send_messages(user_agent& ua,
        const std::shared_ptr<messages_send_extra>& extra,
        const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& single_callback)
    : query(ua, "send messages (single)", TYPE_TO_PARAM(updates))
    , m_extra(extra)
    , m_single_callback(single_callback)
    , m_multi_callback(nullptr)
    , m_bool_callback(nullptr)
    , m_message(nullptr)
{
    assert(m_extra);
    assert(!m_extra->multi);
}

query_send_messages::query_send_messages(user_agent& ua,
        const std::shared_ptr<messages_send_extra>& extra,
        const std::function<void(bool success, const std::vector<std::shared_ptr<tgl_message>>& messages)>& multi_callback)
    : query(ua, "send messages (multi)", TYPE_TO_PARAM(updates))
    , m_extra(extra)
    , m_single_callback(nullptr)
    , m_multi_callback(multi_callback)
    , m_bool_callback(nullptr)
    , m_message(nullptr)
{
    assert(m_extra);
    assert(m_extra->multi);
}

query_send_messages::query_send_messages(user_agent& ua,
        const std::function<void(bool)>& bool_callback)
    : query(ua, "send messages (bool callback)", TYPE_TO_PARAM(updates))
    , m_extra(nullptr)
    , m_single_callback(nullptr)
    , m_multi_callback(nullptr)
    , m_bool_callback(bool_callback)
    , m_message(nullptr)
{ }

void query_send_messages::on_answer(void* D)
{
    const tl_ds_updates* DS_U = static_cast<const tl_ds_updates*>(D);

    m_user_agent.updater().work_any_updates(DS_U, m_message);

    if (!m_extra) {
        if (m_bool_callback) {
            m_bool_callback(true);
        }
    } else if (m_extra->multi) {
        std::vector<std::shared_ptr<tgl_message>> messages;
#if 0 // FIXME
        int count = E->count;
        int i;
        for (i = 0; i < count; i++) {
            int y = tgls_get_local_by_random(E->message_ids[i]);
            ML[i] = tgl_message_get(y);
        }
#endif
        if (m_multi_callback) {
            m_multi_callback(true, messages);
        }
    } else {
#if 0 // FIXME
        int y = tgls_get_local_by_random(E->id);
        struct tgl_message* M = tgl_message_get(y);
#endif
        std::shared_ptr<tgl_message> M;
        if (m_single_callback) {
            m_single_callback(true, M);
        }
    }
}

int query_send_messages::on_error(int error_code, const std::string& error_string)
{
    TGL_ERROR("RPC_CALL_FAIL " <<  error_code << " " << error_string);

    if (!m_extra) {
        if (m_bool_callback) {
            m_bool_callback(false);
        }
    } else if (m_extra->multi) {
        if (m_multi_callback) {
            m_multi_callback(false, std::vector<std::shared_ptr<tgl_message>>());
        }
    } else {
        if (m_single_callback) {
            m_single_callback(false, nullptr);
        }
    }
    return 0;
}

void query_send_messages::set_message(const std::shared_ptr<class message>& message)
{
    m_message = message;
}

}
}
