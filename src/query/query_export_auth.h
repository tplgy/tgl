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

#ifndef __TGL_QUERY_EXPORT_AUTH_H__
#define __TGL_QUERY_EXPORT_AUTH_H__

#include "query.h"
#include "query_import_auth.h"

#include <memory>
#include <functional>

class mtproto_client;

class query_export_auth: public query
{
public:
    query_export_auth(const std::shared_ptr<mtproto_client>& client,
            const std::function<void(bool)>& callback)
        : query("export authorization", TYPE_TO_PARAM(auth_exported_authorization))
        , m_client(client)
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        TGL_DEBUG("export_auth_on_answer " << m_client->id());
        auto ua = get_user_agent();
        if (!ua) {
            TGL_ERROR("the user agent has gone");
            if (m_callback) {
                m_callback(false);
            }
            return;
        }

        tl_ds_auth_exported_authorization* DS_EA = static_cast<tl_ds_auth_exported_authorization*>(D);
        ua->set_our_id(DS_LVAL(DS_EA->id));

        auto q = std::make_shared<query_import_auth>(m_client, m_callback);
        q->out_header(ua.get());
        q->out_i32(CODE_auth_import_authorization);
        q->out_i32(ua->our_id().peer_id);
        q->out_string(DS_STR(DS_EA->bytes));
        q->execute(m_client, query::execution_option::LOGIN);
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
    std::shared_ptr<mtproto_client> m_client;
    std::function<void(bool)> m_callback;
};

#endif
