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

#ifndef __TGL_QUERY_IMPORT_AUTH_H__
#define __TGL_QUERY_IMPORT_AUTH_H__

#include "query.h"

class query_import_auth: public query
{
public:
    query_import_auth(const std::shared_ptr<mtproto_client>& client,
            const std::function<void(bool)>& callback)
        : query("import authorization", TYPE_TO_PARAM(auth_authorization))
        , m_client(client)
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        tl_ds_auth_authorization* DS_U = static_cast<tl_ds_auth_authorization*>(D);
        tglf_fetch_alloc_user(DS_U->user);

        assert(m_client);
        TGL_NOTICE("auth imported from DC " << tgl_state::instance()->active_client()->id() << " to DC " << m_client->id());

        tgl_state::instance()->set_dc_logged_in(m_client->id());

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
    std::shared_ptr<mtproto_client> m_client;
    std::function<void(bool)> m_callback;
};

#endif
