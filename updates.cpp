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
    Copyright Topology LP 2016
*/
#include "tgl.h"
#include "updates.h"
#include "auto/auto.h"
#include "auto/auto-types.h"
#include "auto/auto-fetch-ds.h"
#include "auto/auto-free-ds.h"
#include "mtproto-common.h"
#include "queries.h"
#include "queries-encrypted.h"
#include "structures.h"
#include "tgl-log.h"
#include "types/tgl_update_callback.h"
#include "types/tgl_secret_chat.h"

#include <assert.h>

bool tgl_check_pts_diff(int32_t pts, int32_t pts_count) {
    TGL_DEBUG("pts = " << pts << ", pts_count = " << pts_count);
    if (!tgl_state::instance()->pts()) {
        return true;
    }

    if (pts < tgl_state::instance()->pts() + pts_count) {
        TGL_NOTICE("duplicate message with pts=" << pts);
        return false;
    }
    if (pts > tgl_state::instance()->pts() + pts_count) {
        TGL_NOTICE("hole in pts: pts = "<< pts <<", count = "<< pts_count <<", cur_pts = "<< tgl_state::instance()->pts());
        tgl_do_get_difference(false, nullptr);
        return false;
    }
    if (tgl_state::instance()->is_diff_locked()) {
        TGL_DEBUG("update during get_difference. pts = " << pts);
        return false;
    }
    TGL_DEBUG("OK update, pts = " << pts);
    return true;
}

static bool tgl_check_qts_diff(int32_t qts, int32_t qts_count)
{
    TGL_NOTICE("qts = " << qts << ", qts_count = " << qts_count);
    if (qts < tgl_state::instance()->qts() + qts_count) {
        TGL_NOTICE("duplicate message (qts = " << qts << ", count = " << qts_count << ", cur_qts = " << tgl_state::instance()->qts() << ")");
        return false;
    }

    if (qts > tgl_state::instance()->qts() + qts_count) {
        TGL_NOTICE("hole in qts (qts = " << qts << ", count = " << qts_count << ", cur_qts = " << tgl_state::instance()->qts() << ")");
        tgl_do_get_difference(false, nullptr);
        return false;
    }

    if (tgl_state::instance()->is_diff_locked()) {
        TGL_WARNING("update during get_difference. qts = " << qts);
        return false;
    }

    TGL_DEBUG("qts = " << qts << " is ok");
    return true;
}

static bool tgl_check_channel_pts_diff(const tgl_peer_id_t& channel_id, int32_t pts, int32_t pts_count)
{
    // TODO: remember channel pts
#if 0
    TGL_DEBUG("channel " << tgl_get_peer_id(channel_id) << ": pts = " << pts << ", pts_count = " << pts_count << ", current_pts = " << E->pts);
    if (!E->pts) {
      return true;
    }
    //assert(tgl_state::instance()->pts);
    if (pts < E->pts + pts_count) {
      TGL_NOTICE("duplicate message with pts=" << pts);
      return false;
    }
    if (pts > E->pts + pts_count) {
      TGL_NOTICE("Hole in pts (pts = " << pts << ", count = " << pts_count << ", cur_pts = " << E->pts);
      tgl_do_get_channel_difference(tgl_get_peer_id(channel_id), 0, 0);
      return false;
    }
    if (E->flags & TGLCHF_DIFF) {
      TGL_DEBUG("Update during get_difference. pts = " << pts);
      return false;
    }
    TGL_DEBUG("OK update, pts = " << pts);
#endif
    return true;
}

static bool tglu_check_seq_diff(int32_t seq)
{
    if (!seq) {
        TGL_DEBUG("seq = " << seq << " is ok");
        return true;
    }

    if (tgl_state::instance()->seq()) {
        if (seq <= tgl_state::instance()->seq()) {
            TGL_NOTICE("duplicate message with seq = " << seq);
            return false;
        }

        if (seq > tgl_state::instance()->seq() + 1) {
            TGL_NOTICE("hole in seq (seq = " << seq <<", cur_seq = " << tgl_state::instance()->seq() << ")");
            tgl_do_get_difference(false, nullptr);
            return false;
        }
        if (tgl_state::instance()->is_diff_locked()) {
            TGL_DEBUG("update during get_difference, seq = " << seq);
            return false;
        }
        TGL_DEBUG("seq = " << seq << " is ok");
        return true;
    } else {
        return false;
    }
}

void tglu_work_update(const tl_ds_update* DS_U, const std::shared_ptr<void>& extra, tgl_update_mode mode)
{
    if (tgl_state::instance()->is_diff_locked()) {
        TGL_WARNING("update during get_difference, dropping update");
        return;
    }

    if (mode == tgl_update_mode::check_and_update_consistency
            && DS_U->pts
            && !tgl_check_pts_diff(DS_LVAL(DS_U->pts), DS_LVAL(DS_U->pts_count))) {
        return;
    }

    if (mode == tgl_update_mode::check_and_update_consistency
            && DS_U->qts
            && !tgl_check_qts_diff(DS_LVAL(DS_U->qts), 1)) {
        return;
    }

    if (DS_U->channel_pts) {
        int32_t channel_id;
        if (DS_U->channel_id) {
            channel_id = DS_LVAL(DS_U->channel_id);
        } else {
            if (!DS_U->message || !DS_U->message->to_id || DS_U->message->to_id->magic != CODE_peer_channel) {
                return;
            }
            channel_id = DS_LVAL(DS_U->message->to_id->channel_id);
        }

        tgl_peer_id_t channel = tgl_peer_id_t(tgl_peer_type::channel, channel_id);
        if (mode == tgl_update_mode::check_and_update_consistency
                && !tgl_check_channel_pts_diff(channel, DS_LVAL(DS_U->channel_pts), DS_LVAL(DS_U->channel_pts_count))) {
            return;
        }
    }

    switch (DS_U->magic) {
    case CODE_update_new_message:
        if (auto message = tglf_fetch_alloc_message(DS_U->message)) {
            tgl_state::instance()->callback()->new_messages({message});
        }
        break;
    case CODE_update_message_id:
        if (auto message = std::static_pointer_cast<tgl_message>(extra)) {
            tgl_state::instance()->callback()->message_id_update(DS_LVAL(DS_U->random_id), DS_LVAL(DS_U->id), DS_LVAL(DS_U->id), message->to_id);
        }
        break;
    case CODE_update_user_typing:
        {
            //tgl_peer_id_t id = tgl_peer_id_t(tgl_peer_type::user, DS_LVAL(DS_U->user_id));
            //tgl_peer_t* U = tgl_peer_get(id);
            enum tgl_typing_status status = tglf_fetch_typing(DS_U->action);
            tgl_state::instance()->callback()->typing_status_changed(DS_LVAL(DS_U->user_id), DS_LVAL(DS_U->user_id), tgl_peer_type::user, status);
        }
        break;
    case CODE_update_chat_user_typing:
        {
            tgl_peer_id_t chat_id = tgl_peer_id_t(tgl_peer_type::chat, DS_LVAL(DS_U->chat_id));
            tgl_peer_id_t id = tgl_peer_id_t(tgl_peer_type::user, DS_LVAL(DS_U->user_id));
            enum tgl_typing_status status = tglf_fetch_typing(DS_U->action);
            tgl_state::instance()->callback()->typing_status_changed(id.peer_id, chat_id.peer_id, tgl_peer_type::chat, status);
        }
        break;
    case CODE_update_user_status:
        {
            tgl_user_status status = tglf_fetch_user_status(DS_U->status);
            tgl_state::instance()->callback()->status_notification(DS_LVAL(DS_U->user_id), status);
        }
        break;
    case CODE_update_user_name:
        {
            uint32_t user_id = DS_LVAL(DS_U->user_id);
            std::map<tgl_user_update_type, std::string> updates;
            updates.emplace(tgl_user_update_type::username, DS_STDSTR(DS_U->username));
            updates.emplace(tgl_user_update_type::firstname, DS_STDSTR(DS_U->first_name));
            updates.emplace(tgl_user_update_type::lastname, DS_STDSTR(DS_U->last_name));
            tgl_state::instance()->callback()->user_update(user_id, updates);
        }
        break;
    case CODE_update_user_photo:
        if (DS_U->photo) {
            tgl_file_location photo_big = tglf_fetch_file_location(DS_U->photo->photo_big);
            tgl_file_location photo_small = tglf_fetch_file_location(DS_U->photo->photo_small);
            tgl_state::instance()->callback()->avatar_update(DS_LVAL(DS_U->user_id), tgl_peer_type::user, photo_small, photo_big);
        }
        break;
    case CODE_update_delete_messages:
        if (DS_U->messages) {
            int count = DS_LVAL(DS_U->messages->cnt);
            for (int i = 0; i < count; ++i) {
                tgl_state::instance()->callback()->message_deleted(**(DS_U->messages->data + i));
            }
        }
        break;
    case CODE_update_chat_participants:
        if (DS_U->participants->magic == CODE_chat_participants) {
            tgl_peer_id_t chat_id = tgl_peer_id_t(tgl_peer_type::chat, DS_LVAL(DS_U->chat_id));
            int count = DS_LVAL(DS_U->participants->participants->cnt);
            std::vector<std::shared_ptr<tgl_chat_participant>> participants;
            for (int i = 0; i < count; ++i) {
                bool admin = false;
                bool creator = false;
                if (DS_U->participants->participants->data[i]->magic == CODE_chat_participant_admin) {
                    admin = true;
                } else if (DS_U->participants->participants->data[i]->magic == CODE_chat_participant_creator) {
                    creator = true;
                    admin = true;
                }
                auto participant = std::make_shared<tgl_chat_participant>();
                participant->user_id = DS_LVAL(DS_U->participants->participants->data[i]->user_id);
                participant->inviter_id = DS_LVAL(DS_U->participants->participants->data[i]->inviter_id);
                participant->date = DS_LVAL(DS_U->participants->participants->data[i]->date);
                participant->is_admin = admin;
                participant->is_creator = creator;
                participants.push_back(participant);
            }
            if (participants.size()) {
                tgl_state::instance()->callback()->chat_update_participants(chat_id.peer_id, participants);
            }
        }
        break;
    case CODE_update_contact_registered:
        tgl_state::instance()->callback()->user_registered(DS_LVAL(DS_U->user_id));
        break;
    case CODE_update_contact_link:
        break;
    case CODE_update_new_authorization:
        tgl_state::instance()->callback()->new_authorization(DS_U->device->data, DS_U->location->data);
        break;
    /*
    case CODE_update_new_geo_chat_message:
        break;
    */
    case CODE_update_new_encrypted_message:
        if (auto message = tglf_fetch_encrypted_message(DS_U->encr_message)) {
            tglf_encrypted_message_received(message);
        }
        break;
    case CODE_update_encryption:
        if (auto secret_chat = tglf_fetch_alloc_encrypted_chat(DS_U->encr_chat)) {
            tgl_state::instance()->callback()->secret_chat_update(secret_chat);
            if (secret_chat->state == tgl_secret_chat_state::ok) {
                tgl_do_send_encr_chat_layer(secret_chat);
            }
        }
        break;
    case CODE_update_encrypted_chat_typing:
        if (auto secret_chat = tgl_state::instance()->secret_chat_for_id(DS_LVAL(DS_U->chat_id))) {
            tgl_state::instance()->callback()->typing_status_changed(secret_chat->user_id, DS_LVAL(DS_U->chat_id),
                    tgl_peer_type::enc_chat, tgl_typing_status::typing);
        }
        break;
    case CODE_update_encrypted_messages_read:
        {
            tgl_peer_id_t id(tgl_peer_type::enc_chat, DS_LVAL(DS_U->chat_id));
            tgl_state::instance()->callback()->messages_mark_read_out(id, DS_LVAL(DS_U->max_date));
        }
        break;
    case CODE_update_chat_participant_add:
        {
            tgl_peer_id_t chat_id = tgl_peer_id_t(tgl_peer_type::chat, DS_LVAL(DS_U->chat_id));
            tgl_peer_id_t user_id = tgl_peer_id_t(tgl_peer_type::user, DS_LVAL(DS_U->user_id));
            tgl_peer_id_t inviter_id = tgl_peer_id_t(tgl_peer_type::user, DS_LVAL(DS_U->inviter_id));
            //int version = DS_LVAL(DS_U->version);

            auto participant = std::make_shared<tgl_chat_participant>();
            participant->user_id = user_id.peer_id;
            participant->inviter_id = inviter_id.peer_id;
            participant->date = tgl_get_system_time();
            tgl_state::instance()->callback()->chat_update_participants(chat_id.peer_id, { participant });
        }
        break;
    case CODE_update_chat_participant_delete:
        {
            tgl_peer_id_t chat_id = tgl_peer_id_t(tgl_peer_type::chat, DS_LVAL(DS_U->chat_id));
            tgl_peer_id_t user_id = tgl_peer_id_t(tgl_peer_type::user, DS_LVAL(DS_U->user_id));
            //int version = DS_LVAL(DS_U->version);

            //bl_do_chat_del_user(C->id, version, user_id.peer_id);
            tgl_state::instance()->callback()->chat_delete_user(chat_id.peer_id, user_id.peer_id);
        }
        break;
    case CODE_update_dc_options:
        {
            int count = DS_LVAL(DS_U->dc_options->cnt);
            for (int i = 0; i < count; ++i) {
                fetch_dc_option(DS_U->dc_options->data[i]);
            }
        }
        break;
    case CODE_update_user_blocked:
        {
            bool blocked = DS_BVAL(DS_U->blocked);
            int32_t peer_id = DS_LVAL(DS_U->user_id);

            std::map<tgl_user_update_type, std::string> updates;
            updates.emplace(tgl_user_update_type::blocked, blocked ? "Yes" : "No");
            tgl_state::instance()->callback()->user_update(peer_id, updates);
        }
        break;
    case CODE_update_notify_settings:
        {
            tl_ds_notify_peer* DS_NP = static_cast<tl_ds_notify_peer*>(DS_U->notify_peer);
            tl_ds_peer_notify_settings* DS_NS = static_cast<tl_ds_peer_notify_settings*>(DS_U->notify_settings);

            if (DS_NP->peer == nullptr) {
                break;
            }

            std::map<tgl_user_update_type, std::string> updates;
            int32_t mute_until = DS_LVAL(DS_NS->mute_until);
            switch (DS_NP->peer->magic) {
                case CODE_peer_user:
                    TGL_NOTICE("update_notify_settings, user_id " << DS_LVAL(DS_NP->peer->user_id) << ", settings " << mute_until);
                    updates.emplace(tgl_user_update_type::mute_until, std::to_string(mute_until));
                    tgl_state::instance()->callback()->user_update(DS_LVAL(DS_NP->peer->user_id) , updates);
                    break;
                case CODE_peer_chat: // group
                    TGL_NOTICE("update_notify_settings, chat_id " << DS_LVAL(DS_NP->peer->chat_id) << ", settings " << mute_until);
                    tgl_state::instance()->callback()->chat_update_notify_settings(DS_LVAL(DS_NP->peer->chat_id), mute_until);
                    break;
                case CODE_peer_channel:
                    TGL_NOTICE("update_notify_settings, channel_id " << DS_LVAL(DS_NP->peer->channel_id) << ", settings " << mute_until);
                    tgl_state::instance()->callback()->channel_update_notify_settings(DS_LVAL(DS_NP->peer->channel_id), mute_until);
                    break;
                default:
                    break;
            }
        }
        break;
    case CODE_update_service_notification:
        TGL_NOTICE("notification " << DS_STDSTR(DS_U->type) << ":" << DS_STDSTR(DS_U->message_text));
        tgl_state::instance()->callback()->notification(DS_U->type->data, DS_U->message_text->data);
        break;
    case CODE_update_privacy:
        TGL_NOTICE("privacy change update");
        break;
    case CODE_update_user_phone:
        {
            int32_t peer_id = DS_LVAL(DS_U->user_id);
            std::map<tgl_user_update_type, std::string> updates;
            updates.emplace(tgl_user_update_type::phone, DS_STDSTR(DS_U->phone));
            tgl_state::instance()->callback()->user_update(peer_id, updates);
        }
        break;
    case CODE_update_read_history_inbox:
        {
            tgl_peer_id_t id = tglf_fetch_peer_id(DS_U->peer);
            tgl_state::instance()->callback()->messages_mark_read_in(id, DS_LVAL(DS_U->max_id));
        }
        break;
    case CODE_update_read_history_outbox:
        {
            tgl_peer_id_t id = tglf_fetch_peer_id(DS_U->peer);
            tgl_state::instance()->callback()->messages_mark_read_out(id, DS_LVAL(DS_U->max_id));
        }
        break;
    case CODE_update_web_page:
        break;
    /*
    case CODE_update_msg_update:
        {
          struct tgl_message* M = tgl_message_get(DS_LVAL(DS_U->id));
          if (M) {
            //bl_do_msg_update(TLS, M->id);
            tgl_state::instance()->callback.new_msg(M);
          }
        }
        break;
    */
    case CODE_update_read_messages_contents:
        break;
    case CODE_update_channel_too_long:
        tgl_do_get_channel_difference(tgl_input_peer_t(tgl_peer_type::channel, DS_LVAL(DS_U->channel_id), 0), nullptr);
        break;
    case CODE_update_channel:
        tgl_do_get_channel_difference(tgl_input_peer_t(tgl_peer_type::channel, DS_LVAL(DS_U->channel_id), 0), nullptr);
        break;
    case CODE_update_channel_group:
        break;
    case CODE_update_new_channel_message:
        if (auto message = tglf_fetch_alloc_message(DS_U->message)) {
            tgl_state::instance()->callback()->new_messages({message});
        }
        break;
    case CODE_update_read_channel_inbox:
        break;
    case CODE_update_delete_channel_messages:
        break;
    case CODE_update_channel_message_views:
        break;
    case CODE_update_chat_admins:
        break;
    case CODE_update_chat_participant_admin:
        break;
    case CODE_update_new_sticker_set:
        break;
    case CODE_update_sticker_sets_order:
        break;
    case CODE_update_sticker_sets:
        break;
    case CODE_update_saved_gifs:
        break;
    case CODE_update_bot_inline_query:
        break;
    default:
        assert(false);
    }

    if (mode != tgl_update_mode::check_and_update_consistency) {
        assert(mode == tgl_update_mode::dont_check_and_update_consistency);
        return;
    }

    if (DS_U->pts) {
        tgl_state::instance()->set_pts(DS_LVAL(DS_U->pts));
    }
    if (DS_U->qts) {
        tgl_state::instance()->set_qts(DS_LVAL(DS_U->qts));
    }
    if (DS_U->channel_pts) {
#if 0 // FIXME
        int channel_id;
        if (DS_U->channel_id) {
          channel_id = DS_LVAL(DS_U->channel_id);
        } else {
          assert(DS_U->message);
          assert(DS_U->message->to_id);
          assert(DS_U->message->to_id->magic == CODE_peer_channel);
          channel_id = DS_LVAL(DS_U->message->to_id->channel_id);
        }

        bl_do_set_channel_pts(channel_id, DS_LVAL(DS_U->channel_pts));
#endif
    }
}

void tglu_work_updates(const tl_ds_updates* DS_U, const std::shared_ptr<void>& extra, tgl_update_mode mode)
{
    if (tgl_state::instance()->is_diff_locked()) {
        return;
    }

    if (mode == tgl_update_mode::check_and_update_consistency
            && !tglu_check_seq_diff(DS_LVAL(DS_U->seq))) {
        return;
    }

    if (DS_U->users) {
        for (int i = 0; i < DS_LVAL(DS_U->users->cnt); ++i) {
            tglf_fetch_alloc_user(DS_U->users->data[i]);
        }
    }

    if (DS_U->chats) {
        for (int i = 0; i < DS_LVAL(DS_U->chats->cnt); ++i) {
            tglf_fetch_alloc_chat(DS_U->chats->data[i]);
        }
    }

    if (DS_U->updates) {
        for (int i = 0; i < DS_LVAL(DS_U->updates->cnt); ++i) {
            tglu_work_update(DS_U->updates->data[i], extra, mode);
        }
    }

    if (mode != tgl_update_mode::check_and_update_consistency) {
        assert(mode == tgl_update_mode::dont_check_and_update_consistency);
        return;
    }

    tgl_state::instance()->set_date(DS_LVAL(DS_U->date));
    tgl_state::instance()->set_seq(DS_LVAL(DS_U->seq));
}

static void tglu_work_updates_combined(const tl_ds_updates* DS_U, tgl_update_mode mode)
{
    if (tgl_state::instance()->is_diff_locked()) {
        return;
    }

    if (mode == tgl_update_mode::check_and_update_consistency
            && !tglu_check_seq_diff(DS_LVAL(DS_U->seq_start))) {
        return;
    }

    for (int i = 0; i < DS_LVAL(DS_U->users->cnt); ++i) {
        tglf_fetch_alloc_user(DS_U->users->data[i]);
    }

    for (int i = 0; i < DS_LVAL(DS_U->chats->cnt); ++i) {
        tglf_fetch_alloc_chat(DS_U->chats->data[i]);
    }

    for (int i = 0; i < DS_LVAL(DS_U->updates->cnt); ++i) {
        tglu_work_update(DS_U->updates->data[i], nullptr, mode);
    }

    if (mode != tgl_update_mode::check_and_update_consistency) {
        assert(mode == tgl_update_mode::dont_check_and_update_consistency);
        return;
    }

    tgl_state::instance()->set_date(DS_LVAL(DS_U->date));
    tgl_state::instance()->set_seq(DS_LVAL(DS_U->seq));
}

void tglu_work_update_short_message(const tl_ds_updates* DS_U, tgl_update_mode mode)
{
    if (tgl_state::instance()->is_diff_locked()) {
        return;
    }

    if (mode == tgl_update_mode::check_and_update_consistency
            && !tgl_check_pts_diff(DS_LVAL(DS_U->pts), DS_LVAL(DS_U->pts_count))) {
        return;
    }

    auto message = tglf_fetch_alloc_message_short(DS_U);
    tgl_state::instance()->callback()->new_messages({message});

    if (tgl_state::instance()->is_diff_locked()) {
        return;
    }

    if (mode != tgl_update_mode::check_and_update_consistency) {
        assert(mode == tgl_update_mode::dont_check_and_update_consistency);
        return;
    }

    tgl_state::instance()->set_pts(DS_LVAL(DS_U->pts));
}

void tglu_work_update_short_chat_message(const tl_ds_updates* DS_U, tgl_update_mode mode)
{
    if (tgl_state::instance()->is_diff_locked()) {
        return;
    }

    if (mode == tgl_update_mode::check_and_update_consistency
            && !tgl_check_pts_diff(DS_LVAL(DS_U->pts), DS_LVAL(DS_U->pts_count))) {
        return;
    }

    if (auto message = tglf_fetch_alloc_message_short_chat(DS_U)) {
        tgl_state::instance()->callback()->new_messages({message});
    }

    if (tgl_state::instance()->is_diff_locked()) {
        return;
    }

#if 0
    assert(M);
    if (1) {
        //bl_do_msg_update(&M->permanent_id);
        tgl_state::instance()->callback()->new_message(M);
    }
#endif

    if (mode != tgl_update_mode::check_and_update_consistency) {
        assert(mode == tgl_update_mode::dont_check_and_update_consistency);
        return;
    }

    tgl_state::instance()->set_pts(DS_LVAL(DS_U->pts));
}

static void tglu_work_updates_too_long(const tl_ds_updates* DS_U, tgl_update_mode mode)
{
    if (tgl_state::instance()->is_diff_locked()) {
        return;
    }

    if (mode != tgl_update_mode::check_and_update_consistency) {
        assert(mode == tgl_update_mode::dont_check_and_update_consistency);
        return;
    }

    TGL_NOTICE("updates too long, getting difference ...");
    tgl_do_get_difference(false, nullptr);
}

static void tglu_work_update_short(const tl_ds_updates* DS_U, tgl_update_mode mode)
{
    if (tgl_state::instance()->is_diff_locked()) {
        return;
    }

    tglu_work_update(DS_U->update, nullptr, mode);
}

static void tglu_work_update_short_sent_message(const tl_ds_updates* DS_U,
        const std::shared_ptr<void>& extra, tgl_update_mode mode)
{
    if (mode == tgl_update_mode::check_and_update_consistency
            && DS_U->pts
            && !tgl_check_pts_diff(DS_LVAL(DS_U->pts), DS_LVAL(DS_U->pts_count))) {
        return;
    }

    if (std::shared_ptr<tgl_message> message = std::static_pointer_cast<tgl_message>(extra)) {
        auto new_message = tglf_fetch_alloc_message_short(DS_U);
        new_message->to_id = message->to_id;
        new_message->message = message->message;
        tgl_state::instance()->callback()->message_id_update(message->permanent_id,  new_message->permanent_id, new_message->seq_no, message->to_id);
        if (new_message->media) {
            tgl_state::instance()->callback()->new_messages({new_message});
        }
    }

    if (mode != tgl_update_mode::check_and_update_consistency) {
        assert(mode == tgl_update_mode::dont_check_and_update_consistency);
        return;
    }

    if (DS_U->pts) {
        tgl_state::instance()->set_pts(DS_LVAL(DS_U->pts));
    }
}

void tglu_work_any_updates(const tl_ds_updates* DS_U, const std::shared_ptr<void>& extra, tgl_update_mode mode)
{
    if (tgl_state::instance()->is_diff_locked()) {
        return;
    }

    switch (DS_U->magic) {
    case CODE_updates_too_long:
        tglu_work_updates_too_long(DS_U, mode);
        return;
    case CODE_update_short_message:
        tglu_work_update_short_message(DS_U, mode);
        return;
    case CODE_update_short_chat_message:
        tglu_work_update_short_chat_message(DS_U, mode);
        return;
    case CODE_update_short:
        tglu_work_update_short(DS_U, mode);
        return;
    case CODE_updates_combined:
        tglu_work_updates_combined(DS_U, mode);
        return;
    case CODE_updates:
        tglu_work_updates(DS_U, extra, mode);
        return;
    case CODE_update_short_sent_message:
        tglu_work_update_short_sent_message(DS_U, extra, mode);
        return;
    default:
        assert(false);
    }
}

void tglu_work_any_updates(tgl_in_buffer* in)
{
    paramed_type type = TYPE_TO_PARAM(updates);
    tl_ds_updates* DS_U = fetch_ds_type_updates(in, &type);
    if (!DS_U) {
        TGL_WARNING("failed to fetch updates from response from the server, likely corrupt data");
        return;
    }

    tglu_work_any_updates(DS_U, nullptr, tgl_update_mode::check_and_update_consistency);
    free_ds_type_updates(DS_U, &type);
}
