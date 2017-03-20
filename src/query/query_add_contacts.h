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
#include "tgl/tgl_update_callback.h"
#include "user.h"

#include <functional>
#include <string>

namespace tgl {
namespace impl {

class query_add_contacts: public query
{
public:
    explicit query_add_contacts(const std::function<void(bool, const std::vector<int32_t>&)>& callback)
        : query("add contacts", TYPE_TO_PARAM(contacts_imported_contacts))
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        tl_ds_contacts_imported_contacts* DS_CIC = static_cast<tl_ds_contacts_imported_contacts*>(D);
        TGL_DEBUG(DS_LVAL(DS_CIC->imported->cnt) << " contact(s) added");
        std::vector<int32_t> users;
        bool success = true;
        if (auto ua = get_user_agent()) {
            int32_t n = DS_LVAL(DS_CIC->users->cnt);
            for (int32_t i = 0; i < n; i++) {
                if (auto u = user::create(DS_CIC->users->data[i])) {
                    ua->user_fetched(u);
                    users.push_back(u->id().peer_id);
                }
            }
        } else {
            success = false;
        }
        if (m_callback) {
            m_callback(success, users);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false, std::vector<int>());
        }
        return 0;
    }

private:
    std::function<void(bool, const std::vector<int>&)> m_callback;
};

}
}
