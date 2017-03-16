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

#include "query_get_blocked_users.h"

#include "structures.h"
#include "tgl/tgl_update_callback.h"
#include "user.h"

namespace tgl {
namespace impl {

query_get_blocked_users::query_get_blocked_users(const std::function<void(std::vector<int32_t>)>& callback)
    : query("get blocked users", TYPE_TO_PARAM(contacts_blocked))
    , m_callback(callback)
{ }

void query_get_blocked_users::on_answer(void* D)
{
    std::vector<int32_t> blocked_contacts;
    if (auto ua = get_user_agent()) {
        tl_ds_contacts_blocked* DS_T = static_cast<tl_ds_contacts_blocked*>(D);
        if (DS_T->blocked && DS_T->users) {
            int n = DS_LVAL(DS_T->blocked->cnt);
            for (int i = 0; i < n; ++i) {
                auto u = std::make_shared<user>(DS_T->users->data[i]);
                u->set_blocked(true);
                blocked_contacts.push_back(u->id().peer_id);
                ua->user_fetched(u);
            }
        }
    }
    if (m_callback) {
        m_callback(blocked_contacts);
    }
}

int query_get_blocked_users::on_error(int error_code, const std::string& error_string)
{
    TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
    if (m_callback) {
        m_callback({});
    }
    return 0;
}

}
}
