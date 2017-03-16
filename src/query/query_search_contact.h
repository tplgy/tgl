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
#include "structures.h"
#include "tgl/tgl_log.h"
#include "user.h"

#include <functional>
#include <string>

namespace tgl {
namespace impl {

class query_search_contact: public query
{
public:
    explicit query_search_contact(const std::function<void(const std::vector<std::shared_ptr<tgl_user>>&,
            const std::vector<std::shared_ptr<tgl_chat>>&)>& callback)
        : query("contact search", TYPE_TO_PARAM(contacts_found))
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        tl_ds_contacts_found* DS_CRU = static_cast<tl_ds_contacts_found*>(D);
        std::vector<std::shared_ptr<tgl_user>> users;
        std::vector<std::shared_ptr<tgl_chat>> chats;
        if (auto ua = get_user_agent()) {
            for (int i = 0; i < DS_LVAL(DS_CRU->users->cnt); i++) {
                users.push_back(std::make_shared<user>(DS_CRU->users->data[i]));
            }
            for (int i = 0; i < DS_LVAL(DS_CRU->chats->cnt); i++) {
                chats.push_back(chat::create(DS_CRU->chats->data[i]));
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
