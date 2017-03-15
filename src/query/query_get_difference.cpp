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

#include "query_get_difference.h"

#include "chat.h"
#include "structures.h"
#include "tgl/tgl_update_callback.h"
#include "updater.h"
#include "user.h"

query_get_difference::query_get_difference(const std::function<void(bool)>& callback)
    : query("get difference", TYPE_TO_PARAM(updates_difference))
    , m_callback(callback)
{ }

void query_get_difference::on_answer(void* D)
{
    TGL_DEBUG("get difference answer");

    tl_ds_updates_difference* DS_UD = static_cast<tl_ds_updates_difference*>(D);

    auto ua = get_user_agent();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        if (m_callback) {
            m_callback(false);
        }
        return;
    }

    assert(ua->is_diff_locked());
    ua->set_diff_locked(false);

    if (DS_UD->magic == CODE_updates_difference_empty) {
        ua->set_date(DS_LVAL(DS_UD->date));
        ua->set_seq(DS_LVAL(DS_UD->seq));
        TGL_DEBUG("empty difference, seq = " << ua->seq());
        if (m_callback) {
            m_callback(true);
        }
    } else {
        for (int32_t i = 0; i < DS_LVAL(DS_UD->users->cnt); i++) {
            ua->user_fetched(std::make_shared<user>(DS_UD->users->data[i]));
        }
        for (int32_t i = 0; i < DS_LVAL(DS_UD->chats->cnt); i++) {
            ua->chat_fetched(chat::create(DS_UD->chats->data[i]));
        }

        for (int i = 0; i < DS_LVAL(DS_UD->other_updates->cnt); i++) {
            ua->updater().work_update(DS_UD->other_updates->data[i], nullptr, tgl_update_mode::dont_check_and_update_consistency);
        }

        int message_count = DS_LVAL(DS_UD->new_messages->cnt);
        std::vector<std::shared_ptr<tgl_message>> messages;
        for (int i = 0; i < message_count; i++) {
            messages.push_back(tglf_fetch_alloc_message(ua.get(), DS_UD->new_messages->data[i]));
        }
        ua->callback()->new_messages(messages);
        messages.clear();

        int encrypted_message_count = DS_LVAL(DS_UD->new_encrypted_messages->cnt);
        for (int i = 0; i < encrypted_message_count; i++) {
            ua->updater().work_encrypted_message(DS_UD->new_encrypted_messages->data[i]);
        }

        if (DS_UD->state) {
            ua->set_pts(DS_LVAL(DS_UD->state->pts));
            ua->set_qts(DS_LVAL(DS_UD->state->qts));
            ua->set_date(DS_LVAL(DS_UD->state->date));
            ua->set_seq(DS_LVAL(DS_UD->state->seq));
        } else {
            ua->set_pts(DS_LVAL(DS_UD->intermediate_state->pts));
            ua->set_qts(DS_LVAL(DS_UD->intermediate_state->qts));
            ua->set_date(DS_LVAL(DS_UD->intermediate_state->date));
            ua->get_difference(false, m_callback);
            return;
        }

        if (m_callback) {
            m_callback(true);
        }
    }
}

int query_get_difference::on_error(int error_code, const std::string& error_string)
{
    TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
    if (m_callback) {
        m_callback(false);
    }
    return 0;
}
