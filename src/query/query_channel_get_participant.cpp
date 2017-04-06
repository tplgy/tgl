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

#include "query_channel_get_participant.h"

#include "channel.h"
#include "tgl/tgl_update_callback.h"
#include "user.h"

namespace tgl {
namespace impl {

query_channel_get_participant::query_channel_get_participant(user_agent& ua,
        int32_t channel_id, const std::function<void(bool)>& callback)
    : query(ua, "channel get participant", TYPE_TO_PARAM(channels_channel_participant))
    , m_channel_id(channel_id)
    , m_callback(callback)
{ }

void query_channel_get_participant::on_answer(void* D)
{
    tl_ds_channels_channel_participant* DS_CP = static_cast<tl_ds_channels_channel_participant*>(D);

    for (int32_t i = 0; i < DS_LVAL(DS_CP->users->cnt); ++i) {
        if (auto u = user::create(DS_CP->users->data[i])) {
            m_user_agent.user_fetched(u);
        }
    }

    if (auto participant = create_channel_participant(DS_CP->participant)) {
        m_user_agent.callback()->channel_update_participants(m_channel_id, {participant});
    }

    if (m_callback) {
        m_callback(true);
    }
}

int query_channel_get_participant::on_error(int error_code, const std::string& error_string)
{
    TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
    if (m_callback) {
        m_callback(false);
    }
    return 0;
}

}
}
