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

#include "query_get_dialogs.h"

#include "chat.h"
#include "message.h"
#include "structures.h"
#include "tgl/tgl_update_callback.h"
#include "user.h"

namespace tgl {
namespace impl {

query_get_dialogs::query_get_dialogs(const std::shared_ptr<get_dialogs_state>& state,
        const std::function<void(bool, const std::vector<tgl_peer_id_t>&, const std::vector<int64_t>&, const std::vector<int>&)>& callback)
    : query("get dialogs", TYPE_TO_PARAM(messages_dialogs))
    , m_state(state)
    , m_callback(callback)
{ }

void query_get_dialogs::on_answer(void* D)
{
    auto ua = m_state->weak_user_agent.lock();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        if (m_callback) {
            m_callback(false, std::vector<tgl_peer_id_t>(), std::vector<int64_t>(), std::vector<int>());
        }
        return;
    }

    tl_ds_messages_dialogs* DS_MD = static_cast<tl_ds_messages_dialogs*>(D);
    int32_t dl_size = DS_LVAL(DS_MD->dialogs->cnt);

    int32_t n = DS_LVAL(DS_MD->chats->cnt);
    for (int32_t i = 0; i < n; ++i) {
        if (auto c = chat::create(DS_MD->chats->data[i])) {
            ua->chat_fetched(c);
        }
    }

    n = DS_LVAL(DS_MD->users->cnt);
    for (int32_t i = 0; i < n; ++i) {
        if (auto u = user::create(DS_MD->users->data[i])) {
            ua->user_fetched(u);
        }
    }

    for (int32_t i = 0; i < dl_size; ++i) {
        struct tl_ds_dialog* DS_D = DS_MD->dialogs->data[i];
        tgl_peer_id_t peer_id = tglf_fetch_peer_id(DS_D->peer);
        m_state->peers.push_back(peer_id);
        m_state->last_message_ids.push_back(DS_LVAL(DS_D->top_message));
        m_state->unread_count.push_back(DS_LVAL(DS_D->unread_count));
        m_state->read_box_max_id.push_back(DS_LVAL(DS_D->read_inbox_max_id));
        if (DS_D->notify_settings && ua) {
            ua->callback()->update_notification_settings(peer_id.peer_id, peer_id.peer_type, DS_LVAL(DS_D->notify_settings->mute_until),
                    DS_BOOL(DS_D->notify_settings->show_previews), DS_STDSTR(DS_D->notify_settings->sound), DS_LVAL(DS_D->notify_settings->events_mask));
        }
    }

    std::vector<std::shared_ptr<tgl_message>> new_messages;
    n = DS_LVAL(DS_MD->messages->cnt);
    for (int32_t i = 0; i < n; ++i) {
        if (auto m = message::create(ua->our_id(), DS_MD->messages->data[i])) {
            new_messages.push_back(m);
        }
    }
    ua->callback()->new_messages(new_messages);

    TGL_DEBUG("dl_size = " << dl_size << ", total = " << m_state->peers.size());

    if (dl_size && static_cast<int>(m_state->peers.size()) < m_state->limit
            && DS_MD->magic == CODE_messages_dialogs_slice
            && static_cast<int>(m_state->peers.size()) < DS_LVAL(DS_MD->count)) {
        if (m_state->peers.size() > 0) {
            m_state->offset_peer = m_state->peers[m_state->peers.size() - 1];
#if 0
            int p = static_cast<int>(m_state->size()) - 1;
            while (p >= 0) {
                struct tgl_message* M = tgl_message_get(m_state->last_message_ids[p]);
                if (M) {
                    m_state->offset_date = M->date;
                    break;
                }
                p --;
            }
#endif
        }
        tgl_do_get_dialog_list(m_state, m_callback);
    } else {
        if (m_callback) {
            m_callback(true, m_state->peers, m_state->last_message_ids, m_state->unread_count);
        }
    }
}

int query_get_dialogs::on_error(int error_code, const std::string& error_string)
{
    TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_code);
    if (m_callback) {
        m_callback(false, std::vector<tgl_peer_id_t>(), std::vector<int64_t>(), std::vector<int>());
    }
    return 0;
}

void tgl_do_get_dialog_list(const std::shared_ptr<get_dialogs_state>& state,
        const std::function<void(bool, const std::vector<tgl_peer_id_t>&, const std::vector<int64_t>&, const std::vector<int>&)>& callback)
{
    auto ua = state->weak_user_agent.lock();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        if (callback) {
            callback(false, std::vector<tgl_peer_id_t>(), std::vector<int64_t>(), std::vector<int>());
        }
        return;
    }

    auto q = std::make_shared<query_get_dialogs>(state, callback);
    if (state->channels) {
        q->out_i32(CODE_channels_get_dialogs);
        q->out_i32(state->offset);
        q->out_i32(state->limit - state->peers.size());
    } else {
        q->out_i32(CODE_messages_get_dialogs);
        q->out_i32(state->offset_date);
        q->out_i32(state->offset);
        //q->out_i32(0);
        if (state->offset_peer.peer_type != tgl_peer_type::unknown) {
            q->out_peer_id(ua.get(), state->offset_peer, 0); // FIXME: do we need an access_hash?
        } else {
            q->out_i32(CODE_input_peer_empty);
        }
        q->out_i32(state->limit - state->peers.size());
    }
    q->execute(ua->active_client());
}

}
}
