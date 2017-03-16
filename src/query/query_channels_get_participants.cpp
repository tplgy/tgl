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

#include "structures.h"
#include "tgl/tgl_update_callback.h"
#include "user.h"

namespace tgl {
namespace impl {

query_channels_get_participants::query_channels_get_participants(const std::shared_ptr<channel_get_participants_state>& state,
        const std::function<void(bool)>& callback)
    : query("channels get participants", TYPE_TO_PARAM(channels_channel_participants))
    , m_state(state)
    , m_callback(callback)
{ }

void query_channels_get_participants::on_answer(void* D)
{
    tl_ds_channels_channel_participants* DS_CP = static_cast<tl_ds_channels_channel_participants*>(D);
    auto ua = m_state->weak_user_agent.lock();
    if (ua) {
        for (int32_t i = 0; i < DS_LVAL(DS_CP->users->cnt); i++) {
            ua->user_fetched(std::make_shared<user>(DS_CP->users->data[i]));
        }
    }

    int count = DS_LVAL(DS_CP->participants->cnt);
    if (m_state->limit > 0) {
        int current_size = static_cast<int>(m_state->participants.size());
        assert(m_state->limit > current_size);
        count = std::min(count, m_state->limit - current_size);
    }
    for (int i = 0; i < count; i++) {
        bool admin = false;
        bool creator = false;
        auto magic = DS_CP->participants->data[i]->magic;
        if (magic == CODE_channel_participant_moderator || magic == CODE_channel_participant_editor) {
            admin = true;
        } else if (magic == CODE_channel_participant_creator) {
            creator = true;
            admin = true;
        }
        auto participant = std::make_shared<tgl_channel_participant>();
        participant->user_id = DS_LVAL(DS_CP->participants->data[i]->user_id);
        participant->inviter_id = DS_LVAL(DS_CP->participants->data[i]->inviter_id);
        participant->date = DS_LVAL(DS_CP->participants->data[i]->date);
        participant->is_creator = creator;
        participant->is_admin = admin;
        m_state->participants.push_back(participant);
    }
    m_state->offset += count;

    if (!count || (m_state->limit > 0 && static_cast<int>(m_state->participants.size()) == m_state->limit)) {
        if (m_state->participants.size() && ua) {
            ua->callback()->channel_update_participants(m_state->channel_id.peer_id, m_state->participants);
        }
        m_callback(true);
    } else {
        tgl_do_get_channel_participants(m_state, m_callback);
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

void tgl_do_get_channel_participants(const std::shared_ptr<struct channel_get_participants_state>& state,
        const std::function<void(bool)>& callback)
{
    auto ua = state->weak_user_agent.lock();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        if (callback) {
            callback(false);
        }
        return;
    }

    auto q = std::make_shared<query_channels_get_participants>(state, callback);
    q->out_i32(CODE_channels_get_participants);
    assert(state->channel_id.peer_type == tgl_peer_type::channel);
    q->out_i32(CODE_input_channel);
    q->out_i32(state->channel_id.peer_id);
    q->out_i64(state->channel_id.access_hash);

    switch (state->type) {
    case tgl_channel_participant_type::admins:
        q->out_i32(CODE_channel_participants_admins);
        break;
    case tgl_channel_participant_type::kicked:
        q->out_i32(CODE_channel_participants_kicked);
        break;
    case tgl_channel_participant_type::recent:
        q->out_i32(CODE_channel_participants_recent);
        break;
    case tgl_channel_participant_type::bots:
        q->out_i32(CODE_channel_participants_bots);
        break;
    }
    q->out_i32(state->offset);
    q->out_i32(state->limit);
    q->execute(ua->active_client());
}

}
}
