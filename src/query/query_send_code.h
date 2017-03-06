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

class query_send_code: public query
{
public:
    explicit query_send_code(const std::function<void(bool, bool, const std::string&)>& callback)
        : query("send code", TYPE_TO_PARAM(auth_sent_code))
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        if (m_callback) {
            tl_ds_auth_sent_code* DS_ASC = static_cast<tl_ds_auth_sent_code*>(D);
            std::string phone_code_hash = DS_STDSTR(DS_ASC->phone_code_hash);
            bool registered = DS_BVAL(DS_ASC->phone_registered);;
            m_callback(true, registered, phone_code_hash);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false, false, std::string());
        }
        return 0;
    }

    virtual void on_timeout() override
    {
        TGL_ERROR("timed out for query #" << msg_id() << " (" << name() << ")");
        if (m_callback) {
            m_callback(false, false, "TIME_OUT");
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
    std::function<void(bool, bool, const std::string)> m_callback;
};
