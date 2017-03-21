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

class query_phone_call: public query
{
public:
    query_phone_call(user_agent& ua, const std::function<void(bool)>& callback)
        : query(ua, "phone call", TYPE_TO_PARAM(bool))
        , m_callback(callback)
    { }

    virtual void on_answer(void*) override
    {
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

    virtual void on_timeout() override
    {
        TGL_ERROR("timed out for query #" << msg_id() << " (" << name() << ")");
        if (m_callback) {
            m_callback(false);
        }
    }

    virtual double timeout_interval() const override
    {
        return 20;
    }

    virtual bool should_retry_on_timeout() const override
    {
        return false;
    }

    virtual void will_be_pending() override
    {
        timeout_within(timeout_interval());
    }

private:
    std::function<void(bool)> m_callback;
};

}
}
