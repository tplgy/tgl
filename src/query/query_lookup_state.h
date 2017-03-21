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

#include <functional>
#include <string>

namespace tgl {
namespace impl {

class query_lookup_state: public query
{
public:
    query_lookup_state(user_agent& ua, const std::function<void(bool)>& callback)
        : query(ua, "lookup state", TYPE_TO_PARAM(updates_state))
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        tl_ds_updates_state* DS_US = static_cast<tl_ds_updates_state*>(D);
        int pts = DS_LVAL(DS_US->pts);
        int qts = DS_LVAL(DS_US->qts);
        int seq = DS_LVAL(DS_US->seq);
        if (pts > m_user_agent.pts() || qts > m_user_agent.qts() || seq > m_user_agent.seq()) {
            m_user_agent.get_difference(false, m_callback);
            return;
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
    std::function<void(bool)> m_callback;
};

}
}
