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

class query_export_chat_link: public query
{
public:
    query_export_chat_link(user_agent& ua, const std::function<void(bool, const std::string&)>& callback)
        : query(ua, "export chat link", TYPE_TO_PARAM(exported_chat_invite))
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        tl_ds_exported_chat_invite* DS_ECI = static_cast<tl_ds_exported_chat_invite*>(D);
        if (m_callback) {
            std::string link;
            if (DS_ECI->link && DS_ECI->link->data) {
                link = std::string(DS_ECI->link->data, DS_ECI->link->len);
            }
            m_callback(true, link);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false, std::string());
        }
        return 0;
    }

private:
    std::function<void(bool, const std::string&)> m_callback;
};

}
}
