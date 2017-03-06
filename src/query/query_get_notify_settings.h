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

class query_get_notify_settings: public query
{
public:
    explicit query_get_notify_settings(
            const std::function<void(bool, int32_t)>& callback)
        : query("get notify settings", TYPE_TO_PARAM(peer_notify_settings))
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        tl_ds_peer_notify_settings* DS_CC = static_cast<tl_ds_peer_notify_settings*>(D);
        int mute_until = DS_LVAL(DS_CC->mute_until);

        if (m_callback) {
            m_callback(true, mute_until);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false, 0);
        }
        return 0;
    }

private:
    std::function<void(bool, int32_t)> m_callback;
};
