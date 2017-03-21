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

#include "chat.h"
#include "query.h"
#include "tgl/tgl_log.h"
#include "user.h"

#include <functional>
#include <string>

namespace tgl {
namespace impl {

class query_search_contact: public query
{
public:
    query_search_contact(user_agent& ua, const std::function<void(const std::vector<std::shared_ptr<tgl_user>>&,
            const std::vector<std::shared_ptr<tgl_chat>>&)>& callback)
        : query(ua, "contact search", TYPE_TO_PARAM(contacts_found))
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        const tl_ds_contacts_found* DS_CRU = static_cast<const tl_ds_contacts_found*>(D);
        std::vector<std::shared_ptr<tgl_user>> users;
        std::vector<std::shared_ptr<tgl_chat>> chats;
        int32_t n = DS_LVAL(DS_CRU->users->cnt);
        for (int32_t i = 0; i < n; ++i) {
            if (auto u = user::create(DS_CRU->users->data[i])) {
                users.push_back(u);
            }
        }
        n = DS_LVAL(DS_CRU->chats->cnt);
        for (int32_t i = 0; i < n; ++i) {
            if (auto c = chat::create(DS_CRU->chats->data[i])) {
                chats.push_back(c);
            }
        }
        if (m_callback) {
            m_callback(users, chats);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_code);
        if (m_callback) {
            m_callback({},{});
        }
        return 0;
    }

private:
    std::function<void(const std::vector<std::shared_ptr<tgl_user>>&,
            const std::vector<std::shared_ptr<tgl_chat>>&)> m_callback;
};

}
}
