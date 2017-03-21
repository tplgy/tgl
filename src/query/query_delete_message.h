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

#pragma once

#include "query.h"
#include "tgl/tgl_log.h"
#include "tgl/tgl_peer_id.h"
#include "tgl/tgl_update_callback.h"
#include "updater.h"

#include <functional>
#include <string>

namespace tgl {
namespace impl {

class query_delete_message: public query
{
public:
    query_delete_message(user_agent& ua, const tgl_input_peer_t& chat, int64_t message_id,
            const std::function<void(bool)>& callback)
        : query(ua, "delete message", TYPE_TO_PARAM(messages_affected_messages))
        , m_chat(chat)
        , m_message_id(message_id)
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        tl_ds_messages_affected_messages* DS_MAM = static_cast<tl_ds_messages_affected_messages*>(D);
        m_user_agent.callback()->message_deleted(m_message_id, m_chat);
        if (m_user_agent.updater().check_pts_diff(DS_LVAL(DS_MAM->pts), DS_LVAL(DS_MAM->pts_count))) {
            m_user_agent.set_pts(DS_LVAL(DS_MAM->pts));
        }

        if (m_callback) {
            m_callback(true);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false);
        }
        return 0;
    }

private:
    tgl_input_peer_t m_chat;
    int64_t m_message_id;
    std::function<void(bool)> m_callback;
};

}
}
