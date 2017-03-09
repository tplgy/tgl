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
#include "user_agent.h"

#include <functional>
#include <string>

class query_mark_message_read: public query
{
public:
    query_mark_message_read(const tgl_input_peer_t& id, int max_id,
            const std::function<void(bool)>& callback)
        : query("mark read", id.peer_type == tgl_peer_type::channel ? TYPE_TO_PARAM(bool) : TYPE_TO_PARAM(messages_affected_messages))
        , m_id(id)
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        if (m_id.peer_type == tgl_peer_type::channel) {
            if (m_callback) {
                m_callback(true);
            }
            // FIXME: should we call mark_messages_read() callback for incoming message? What should we pass for msg_id?
            return;
        }

        tl_ds_messages_affected_messages* DS_MAM = static_cast<tl_ds_messages_affected_messages*>(D);

        if (auto ua = get_user_agent()) {
            if (ua->updater().check_pts_diff(DS_LVAL(DS_MAM->pts), DS_LVAL(DS_MAM->pts_count))) {
                ua->set_pts(DS_LVAL(DS_MAM->pts));
            }
            ua->callback()->mark_messages_read(false, tgl_peer_id_t::from_input_peer(m_id), DS_LVAL(DS_MAM->pts));
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

    virtual double timeout_interval() const override
    {
        return 120;
    }

private:
    tgl_input_peer_t m_id;
    std::function<void(bool)> m_callback;
};
