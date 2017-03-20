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
#include "user.h"

namespace tgl {
namespace impl {

class query_user_info: public query
{
public:
    explicit query_user_info(const std::function<void(bool, const std::shared_ptr<user>&)>& callback)
        : query("user info", TYPE_TO_PARAM(user_full))
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        auto ua = get_user_agent();
        if (!ua) {
            if (m_callback) {
                m_callback(false, nullptr);
            }
            return;
        }

        auto DS_UF = static_cast<tl_ds_user_full*>(D);
        std::shared_ptr<user> u;
        if (DS_UF->user && DS_UF->user->magic != CODE_user_empty) {
            u = user::create(DS_UF);
            if (u) {
                ua->user_fetched(u);
            }
        }

        if (m_callback) {
            m_callback(!!u, u);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false, nullptr);
        }
        return 0;
    }

private:
    std::function<void(bool, const std::shared_ptr<user>&)> m_callback;
};

}
}
