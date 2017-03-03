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

#include "auto/auto.h"
#include "mtproto_client.h"
#include "query.h"
#include "tgl/tgl_log.h"

#include <cstdint>
#include <memory>

class query_bind_temp_auth_key: public query
{
public:
    query_bind_temp_auth_key(const std::shared_ptr<mtproto_client>& client, int64_t message_id)
        : query("bind temp auth key", TYPE_TO_PARAM(bool), message_id)
        , m_client(client)
    { }

    virtual void on_answer(void*) override
    {
        m_client->set_bound();
        TGL_DEBUG("bind temp auth key successfully for DC " << m_client->id());
        m_client->configure();
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_WARNING("bind temp auth key error " << error_code << " " << error_string << " for DC " << m_client->id());
        if (error_code == 400) {
            m_client->restart_temp_authorization();
        }
        return 0;
    }

    virtual void on_timeout() override
    {
        TGL_WARNING("bind timed out for DC " << m_client->id());
        m_client->restart_temp_authorization();
    }

    virtual bool should_retry_on_timeout() const override
    {
        return false;
    }

    virtual bool should_retry_after_recover_from_error() const override
    {
        return false;
    }

private:
    std::shared_ptr<mtproto_client> m_client;
};
