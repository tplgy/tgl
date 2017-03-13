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

class query_get_state: public query
{
public:
    explicit query_get_state(const std::function<void(bool)>& callback)
        : query("get state", TYPE_TO_PARAM(updates_state))
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        bool success = true;
        if (auto ua = get_user_agent()) {
            assert(ua->is_diff_locked());
            tl_ds_updates_state* DS_US = static_cast<tl_ds_updates_state*>(D);
            ua->set_diff_locked(false);
            ua->set_pts(DS_LVAL(DS_US->pts));
            ua->set_qts(DS_LVAL(DS_US->qts));
            ua->set_date(DS_LVAL(DS_US->date));
            ua->set_seq(DS_LVAL(DS_US->seq));
        } else {
            success = false;
        }

        if (m_callback) {
            m_callback(success);
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