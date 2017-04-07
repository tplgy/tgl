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

#include "query_channels_get_participants.h"

#include "channel.h"
#include "tgl/tgl_update_callback.h"
#include "user.h"

namespace tgl {
namespace impl {

query_channels_get_participants::query_channels_get_participants(user_agent& ua, 
        const std::shared_ptr<channel_get_participants_state>& state,
        const std::function<void(bool)>& callback)
    : query(ua, "channels get participants", TYPE_TO_PARAM(channels_channel_participants))
    , m_state(state)
    , m_callback(callback)
{
    assemble();
}

void query_channels_get_participants::on_answer(void* D)
{
    tl_ds_channels_channel_participants* DS_CP = static_cast<tl_ds_channels_channel_participants*>(D);
    for (int32_t i = 0; i < DS_LVAL(DS_CP->users->cnt); ++i) {
        if (auto u = user::create(DS_CP->users->data[i])) {
            m_user_agent.user_fetched(u);
        }
    }

    int32_t count = DS_LVAL(DS_CP->participants->cnt);
    if (m_state->limit > 0) {
        int current_size = static_cast<int>(m_state->participants.size());
        assert(m_state->limit > current_size);
        count = std::min(count, m_state->limit - current_size);
    }
    for (int32_t i = 0; i < count; ++i) {
        if (auto participant = create_channel_participant(DS_CP->participants->data[i])) {
            m_state->participants.push_back(participant);
        }
    }
    m_state->offset += count;

    if (!count || (m_state->limit > 0 && static_cast<int>(m_state->participants.size()) == m_state->limit)) {
        if (m_state->participants.size()) {
            m_user_agent.callback()->channel_update_participants(m_state->channel_id.peer_id, m_state->participants);
        }
        m_callback(true);
    } else {
        get_more();
    }
}

int query_channels_get_participants::on_error(int error_code, const std::string& error_string)
{
    TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
    if (m_callback) {
        m_callback(false);
    }
    return 0;
}

void query_channels_get_participants::assemble()
{
    assert(m_state->channel_id.peer_type == tgl_peer_type::channel);

    out_i32(CODE_channels_get_participants);
    out_i32(CODE_input_channel);
    out_i32(m_state->channel_id.peer_id);
    out_i64(m_state->channel_id.access_hash);

    switch (m_state->filter) {
    case tgl_channel_participant_filter::admins:
        out_i32(CODE_channel_participants_admins);
        break;
    case tgl_channel_participant_filter::kicked:
        out_i32(CODE_channel_participants_kicked);
        break;
    case tgl_channel_participant_filter::recent:
        out_i32(CODE_channel_participants_recent);
        break;
    case tgl_channel_participant_filter::bots:
        out_i32(CODE_channel_participants_bots);
        break;
    }
    out_i32(m_state->offset);
    out_i32(m_state->limit);
}

void query_channels_get_participants::get_more()
{
    auto q = std::make_shared<query_channels_get_participants>(m_user_agent, m_state, m_callback);
    q->execute(client());
}

}
}
