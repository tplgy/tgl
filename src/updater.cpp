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

#include "updater.h"

#include "auto/auto.h"
#include "auto/auto-types.h"
#include "auto/auto-fetch-ds.h"
#include "auto/auto-free-ds.h"
#include "chat.h"
#include "file_location.h"
#include "message.h"
#include "mtproto_common.h"
#include "peer_id.h"
#include "secret_chat.h"
#include "tgl/tgl_log.h"
#include "tgl/tgl_update_callback.h"
#include "typing_status.h"
#include "user.h"
#include "user_agent.h"
#include "webpage.h"

#include <cassert>

namespace tgl {
namespace impl {

bool updater::check_pts_diff(int32_t pts, int32_t pts_count)
{
    TGL_DEBUG("pts = " << pts << ", pts_count = " << pts_count);
    if (!m_user_agent.pts()) {
        return true;
    }

    if (pts_count == 0) {
        // no change in pts, so it's allowed
        return true;
    }

    if (pts < m_user_agent.pts() + pts_count) {
        TGL_NOTICE("duplicate message with pts=" << pts);
        return false;
    }
    if (pts > m_user_agent.pts() + pts_count) {
        TGL_NOTICE("hole in pts: pts = "<< pts <<", count = "<< pts_count <<", cur_pts = "<< m_user_agent.pts());
        m_user_agent.get_difference(false, nullptr);
        return false;
    }
    if (m_user_agent.is_diff_locked()) {
        TGL_DEBUG("update during get_difference. pts = " << pts);
        return false;
    }
    TGL_DEBUG("OK update, pts = " << pts);
    return true;
}

bool updater::check_qts_diff(int32_t qts, int32_t qts_count)
{
    TGL_DEBUG("qts = " << qts << ", qts_count = " << qts_count);
    if (qts < m_user_agent.qts() + qts_count) {
        TGL_NOTICE("duplicate message (qts = " << qts << ", count = " << qts_count << ", cur_qts = " << m_user_agent.qts() << ")");
        // Better off getting difference to corret our qts. Our locally qts could be invalid if we
        // got logged out and we didn't know about it. Even if it is a real dup we will ignore
        // the duplicated message because secret chat itself have its own sequence number.
        m_user_agent.get_difference(false, nullptr);
        return false;
    }

    if (qts > m_user_agent.qts() + qts_count) {
        TGL_NOTICE("hole in qts (qts = " << qts << ", count = " << qts_count << ", cur_qts = " << m_user_agent.qts() << ")");
        m_user_agent.get_difference(false, nullptr);
        return false;
    }

    if (m_user_agent.is_diff_locked()) {
        TGL_WARNING("update during get_difference. qts = " << qts);
        return false;
    }

    TGL_DEBUG("qts = " << qts << " is ok");
    return true;
}

bool updater::check_channel_pts_diff(const tgl_peer_id_t& channel_id, int32_t pts, int32_t pts_count)
{
    // TODO: remember channel pts
#if 0
    TGL_DEBUG("channel " << tgl_get_peer_id(channel_id) << ": pts = " << pts << ", pts_count = " << pts_count << ", current_pts = " << E->pts);
    if (!E->pts) {
      return true;
    }
    //assert(m_user_agent.pts());
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

bool updater::check_seq_diff(int32_t seq)
{
    if (!seq) {
        TGL_DEBUG("seq = " << seq << " is ok");
        return true;
    }

    if (m_user_agent.seq()) {
        if (seq <= m_user_agent.seq()) {
            TGL_NOTICE("duplicate message with seq = " << seq);
            return false;
        }

        if (seq > m_user_agent.seq() + 1) {
            TGL_NOTICE("hole in seq (seq = " << seq <<", cur_seq = " << m_user_agent.seq() << ")");
            m_user_agent.get_difference(false, nullptr);
            return false;
        }
        if (m_user_agent.is_diff_locked()) {
            TGL_DEBUG("update during get_difference, seq = " << seq);
            return false;
        }
        TGL_DEBUG("seq = " << seq << " is ok");
        return true;
    } else {
        return false;
    }
}

void updater::work_update(const tl_ds_update* DS_U, const std::shared_ptr<void>& extra, update_mode mode)
{
    if (m_user_agent.is_diff_locked()) {
        TGL_WARNING("update during get_difference, dropping update");
        return;
    }

    if (mode == update_mode::check_and_update_consistency
            && DS_U->pts
            && !check_pts_diff(DS_LVAL(DS_U->pts), DS_LVAL(DS_U->pts_count))) {
        return;
    }

    if (mode == update_mode::check_and_update_consistency
            && DS_U->qts
            && !check_qts_diff(DS_LVAL(DS_U->qts), 1)) {
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
        if (mode == update_mode::check_and_update_consistency
                && !check_channel_pts_diff(channel, DS_LVAL(DS_U->channel_pts), DS_LVAL(DS_U->channel_pts_count))) {
            return;
        }
    }

    switch (DS_U->magic) {
    case CODE_update_new_message:
        if (auto m = message::create(m_user_agent.our_id(), DS_U->message)) {
            m_user_agent.callback()->new_messages({m});
        }
        break;
    case CODE_update_message_id:
        if (auto message = std::static_pointer_cast<tgl_message>(extra)) {
            m_user_agent.callback()->message_id_updated(DS_LVAL(DS_U->random_id), DS_LVAL(DS_U->id), message->to_id());
        } else {
            m_user_agent.callback()->message_id_updated(DS_LVAL(DS_U->random_id), DS_LVAL(DS_U->id), tgl_input_peer_t());
        }
        break;
    case CODE_update_user_typing:
        {
            //tgl_peer_id_t id = tgl_peer_id_t(tgl_peer_type::user, DS_LVAL(DS_U->user_id));
            //tgl_peer_t* U = tgl_peer_get(id);
            enum tgl_typing_status status = create_typing_status(DS_U->action);
            m_user_agent.callback()->typing_status_changed(DS_LVAL(DS_U->user_id), DS_LVAL(DS_U->user_id), tgl_peer_type::user, status);
        }
        break;
    case CODE_update_chat_user_typing:
        {
            tgl_peer_id_t chat_id = tgl_peer_id_t(tgl_peer_type::chat, DS_LVAL(DS_U->chat_id));
            tgl_peer_id_t id = tgl_peer_id_t(tgl_peer_type::user, DS_LVAL(DS_U->user_id));
            enum tgl_typing_status status = create_typing_status(DS_U->action);
            m_user_agent.callback()->typing_status_changed(id.peer_id, chat_id.peer_id, tgl_peer_type::chat, status);
        }
        break;
    case CODE_update_user_status:
        {
            tgl_user_status status = create_user_status(DS_U->status);
            m_user_agent.callback()->status_notification(DS_LVAL(DS_U->user_id), status);
        }
        break;
    case CODE_update_user_name:
        {
            uint32_t user_id = DS_LVAL(DS_U->user_id);
            std::map<tgl_user_update_type, std::string> updates;
            updates.emplace(tgl_user_update_type::username, DS_STDSTR(DS_U->username));
            updates.emplace(tgl_user_update_type::firstname, DS_STDSTR(DS_U->first_name));
            updates.emplace(tgl_user_update_type::lastname, DS_STDSTR(DS_U->last_name));
            m_user_agent.callback()->user_update(user_id, updates);
        }
        break;
    case CODE_update_user_photo:
        if (DS_U->photo) {
            tgl_file_location photo_big = create_file_location(DS_U->photo->photo_big);
            tgl_file_location photo_small = create_file_location(DS_U->photo->photo_small);
            m_user_agent.callback()->avatar_update(DS_LVAL(DS_U->user_id), tgl_peer_type::user, photo_small, photo_big);
        }
        break;
    case CODE_update_delete_messages:
    case CODE_update_delete_channel_messages:
        if (DS_U->messages) {
            int count = DS_LVAL(DS_U->messages->cnt);
            for (int i = 0; i < count; ++i) {
                m_user_agent.callback()->message_deleted(**(DS_U->messages->data + i), tgl_input_peer_t());
            }
        }
        break;
    case CODE_update_chat_participants:
        if (DS_U->participants->magic == CODE_chat_participants) {
            tgl_peer_id_t chat_id = tgl_peer_id_t(tgl_peer_type::chat, DS_LVAL(DS_U->participants->chat_id));
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
                m_user_agent.callback()->chat_update_participants(chat_id.peer_id, participants);
            }
        }
        break;
    case CODE_update_contact_registered:
        m_user_agent.callback()->user_registered(DS_LVAL(DS_U->user_id));
        break;
    case CODE_update_contact_link:
        break;
    case CODE_update_new_authorization:
        m_user_agent.callback()->new_authorization(DS_U->device->data, DS_U->location->data);
        break;
    /*
    case CODE_update_new_geo_chat_message:
        break;
    */
    case CODE_update_new_encrypted_message:
        work_encrypted_message(DS_U->encr_message);
        break;
    case CODE_update_encryption:
        if (auto sc = m_user_agent.allocate_or_update_secret_chat(DS_U->encr_chat)) {
            m_user_agent.callback()->secret_chat_update(sc);
            if (sc->state() == tgl_secret_chat_state::ok) {
                sc->send_layer();
            }
        }
        break;
    case CODE_update_encrypted_chat_typing:
        if (auto sc = m_user_agent.secret_chat_for_id(DS_LVAL(DS_U->chat_id))) {
            m_user_agent.callback()->typing_status_changed(sc->user_id(), DS_LVAL(DS_U->chat_id),
                    tgl_peer_type::enc_chat, tgl_typing_status::typing);
        }
        break;
    case CODE_update_encrypted_messages_read:
        {
            tgl_peer_id_t id(tgl_peer_type::enc_chat, DS_LVAL(DS_U->chat_id));
            m_user_agent.callback()->mark_messages_read(true, id, DS_LVAL(DS_U->max_date));
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
            m_user_agent.callback()->chat_update_participants(chat_id.peer_id, { participant });
        }
        break;
    case CODE_update_chat_participant_delete:
        {
            tgl_peer_id_t chat_id = tgl_peer_id_t(tgl_peer_type::chat, DS_LVAL(DS_U->chat_id));
            tgl_peer_id_t user_id = tgl_peer_id_t(tgl_peer_type::user, DS_LVAL(DS_U->user_id));
            //int version = DS_LVAL(DS_U->version);

            //bl_do_chat_del_user(C->id, version, user_id.peer_id);
            m_user_agent.callback()->chat_delete_user(chat_id.peer_id, user_id.peer_id);
        }
        break;
    case CODE_update_dc_options:
        {
            int count = DS_LVAL(DS_U->dc_options->cnt);
            for (int i = 0; i < count; ++i) {
                m_user_agent.fetch_dc_option(DS_U->dc_options->data[i]);
            }
        }
        break;
    case CODE_update_user_blocked:
        {
            bool blocked = DS_BVAL(DS_U->blocked);
            int32_t peer_id = DS_LVAL(DS_U->user_id);

            std::map<tgl_user_update_type, std::string> updates;
            updates.emplace(tgl_user_update_type::blocked, blocked ? "Yes" : "No");
            m_user_agent.callback()->user_update(peer_id, updates);
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
            std::string notification_sound = DS_STDSTR(DS_NS->sound);
            bool show_previews = DS_BOOL(DS_NS->show_previews);
            int32_t event_mask = DS_LVAL(DS_NS->events_mask);
            int32_t peer_id = 0;
            tgl_peer_type peer_type = tgl_peer_type::unknown;

            switch (DS_NP->peer->magic) {
                case CODE_peer_user:
                    peer_id = DS_LVAL(DS_NP->peer->user_id);
                    peer_type = tgl_peer_type::user;
                    break;
                case CODE_peer_chat: // group
                    peer_id = DS_LVAL(DS_NP->peer->chat_id);
                    peer_type = tgl_peer_type::chat;
                    break;
                case CODE_peer_channel:
                    peer_id = DS_LVAL(DS_NP->peer->channel_id);
                    peer_type = tgl_peer_type::channel;
                    break;
                default:
                    break;
            }
            if (peer_type != tgl_peer_type::unknown && peer_id != 0) {
                TGL_DEBUG("update_notify_settings, peer_id " << peer_id << " type " << static_cast<int32_t>(peer_type) << "; mute until " << mute_until
                           << " show previews " << show_previews << " sound " << notification_sound);
                m_user_agent.callback()->update_notification_settings(peer_id, peer_type, mute_until,
                        show_previews, notification_sound, event_mask);
            }
        }
        break;
    case CODE_update_service_notification:
        TGL_DEBUG("notification " << DS_STDSTR(DS_U->type) << ":" << DS_STDSTR(DS_U->message_text));
        m_user_agent.callback()->notification(DS_STDSTR(DS_U->type), DS_STDSTR(DS_U->message_text));
        break;
    case CODE_update_privacy:
        TGL_DEBUG("privacy change update");
        break;
    case CODE_update_user_phone:
        {
            int32_t peer_id = DS_LVAL(DS_U->user_id);
            std::map<tgl_user_update_type, std::string> updates;
            updates.emplace(tgl_user_update_type::phone, DS_STDSTR(DS_U->phone));
            m_user_agent.callback()->user_update(peer_id, updates);
        }
        break;
    case CODE_update_read_history_inbox:
        {
            tgl_peer_id_t id = create_peer_id(DS_U->peer);
            m_user_agent.callback()->mark_messages_read(false, id, DS_LVAL(DS_U->max_id));
        }
        break;
    case CODE_update_read_history_outbox:
        {
            tgl_peer_id_t id = create_peer_id(DS_U->peer);
            m_user_agent.callback()->mark_messages_read(true, id, DS_LVAL(DS_U->max_id));
        }
        break;
    case CODE_update_web_page: {
        auto media = std::make_shared<tgl_message_media_webpage>();
        media->webpage = webpage::create(DS_U->webpage);
        m_user_agent.callback()->message_media_webpage_updated(media);
        break;
    }
    case CODE_update_read_messages_contents:
        break;
    case CODE_update_channel_too_long:
        m_user_agent.get_channel_difference(tgl_input_peer_t(tgl_peer_type::channel, DS_LVAL(DS_U->channel_id), 0), nullptr);
        break;
    case CODE_update_channel:
        m_user_agent.get_channel_difference(tgl_input_peer_t(tgl_peer_type::channel, DS_LVAL(DS_U->channel_id), 0), nullptr);
        break;
    case CODE_update_channel_group:
        break;
    case CODE_update_new_channel_message:
        if (auto m = message::create(m_user_agent.our_id(), DS_U->message)) {
            m_user_agent.callback()->new_messages({m});
        }
        break;
    case CODE_update_read_channel_inbox:
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

    if (mode != update_mode::check_and_update_consistency) {
        assert(mode == update_mode::dont_check_and_update_consistency);
        return;
    }

    if (DS_U->pts) {
        m_user_agent.set_pts(DS_LVAL(DS_U->pts));
    }
    if (DS_U->qts) {
        m_user_agent.set_qts(DS_LVAL(DS_U->qts));
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

void updater::work_updates(const tl_ds_updates* DS_U, const std::shared_ptr<void>& extra, update_mode mode)
{
    if (m_user_agent.is_diff_locked()) {
        return;
    }

    if (mode == update_mode::check_and_update_consistency
            && !check_seq_diff(DS_LVAL(DS_U->seq))) {
        return;
    }

    if (DS_U->users) {
        int32_t n = DS_LVAL(DS_U->users->cnt);
        for (int32_t i = 0; i < n; ++i) {
            if (auto u = user::create(DS_U->users->data[i])) {
                m_user_agent.user_fetched(u);
            }
        }
    }

    if (DS_U->chats) {
        int32_t n = DS_LVAL(DS_U->chats->cnt);
        for (int32_t i = 0; i < n; ++i) {
            if (auto c = chat::create(DS_U->chats->data[i])) {
                m_user_agent.chat_fetched(c);
            }
        }
    }

    if (DS_U->updates) {
        int32_t n = DS_LVAL(DS_U->updates->cnt);
        for (int32_t i = 0; i < n; ++i) {
            work_update(DS_U->updates->data[i], extra, mode);
        }
    }

    if (mode != update_mode::check_and_update_consistency) {
        assert(mode == update_mode::dont_check_and_update_consistency);
        return;
    }

    m_user_agent.set_date(DS_LVAL(DS_U->date));
    m_user_agent.set_seq(DS_LVAL(DS_U->seq));
}

void updater::work_updates_combined(const tl_ds_updates* DS_U, update_mode mode)
{
    if (m_user_agent.is_diff_locked()) {
        return;
    }

    if (mode == update_mode::check_and_update_consistency
            && !check_seq_diff(DS_LVAL(DS_U->seq_start))) {
        return;
    }

    int32_t n = DS_LVAL(DS_U->users->cnt);
    for (int32_t i = 0; i < n; ++i) {
        if (auto u = user::create(DS_U->users->data[i])) {
            m_user_agent.user_fetched(u);
        }
    }

    n = DS_LVAL(DS_U->chats->cnt);
    for (int32_t i = 0; i < n; ++i) {
        if (auto c = chat::create(DS_U->chats->data[i])) {
            m_user_agent.chat_fetched(c);
        }
    }

    n = DS_LVAL(DS_U->updates->cnt);
    for (int32_t i = 0; i < n; ++i) {
        work_update(DS_U->updates->data[i], nullptr, mode);
    }

    if (mode != update_mode::check_and_update_consistency) {
        assert(mode == update_mode::dont_check_and_update_consistency);
        return;
    }

    m_user_agent.set_date(DS_LVAL(DS_U->date));
    m_user_agent.set_seq(DS_LVAL(DS_U->seq));
}

void updater::work_update_short_message(const tl_ds_updates* DS_U, update_mode mode)
{
    if (m_user_agent.is_diff_locked()) {
        return;
    }

    if (mode == update_mode::check_and_update_consistency
            && !check_pts_diff(DS_LVAL(DS_U->pts), DS_LVAL(DS_U->pts_count))) {
        return;
    }

    if (auto m = message::create_from_short_update(m_user_agent.our_id(), DS_U)) {
        m_user_agent.callback()->new_messages({m});
    }

    if (m_user_agent.is_diff_locked()) {
        return;
    }

    if (mode != update_mode::check_and_update_consistency) {
        assert(mode == update_mode::dont_check_and_update_consistency);
        return;
    }

    m_user_agent.set_pts(DS_LVAL(DS_U->pts));
}

void updater::work_update_short_chat_message(const tl_ds_updates* DS_U, update_mode mode)
{
    if (m_user_agent.is_diff_locked()) {
        return;
    }

    if (mode == update_mode::check_and_update_consistency
            && !check_pts_diff(DS_LVAL(DS_U->pts), DS_LVAL(DS_U->pts_count))) {
        return;
    }

    if (auto m = message::create_chat_message_from_short_update(DS_U)) {
        m_user_agent.callback()->new_messages({m});
    }

    if (m_user_agent.is_diff_locked()) {
        return;
    }

    if (mode != update_mode::check_and_update_consistency) {
        assert(mode == update_mode::dont_check_and_update_consistency);
        return;
    }

    m_user_agent.set_pts(DS_LVAL(DS_U->pts));
}

void updater::work_updates_too_long(const tl_ds_updates* DS_U, update_mode mode)
{
    if (m_user_agent.is_diff_locked()) {
        return;
    }

    if (mode != update_mode::check_and_update_consistency) {
        assert(mode == update_mode::dont_check_and_update_consistency);
        return;
    }

    TGL_DEBUG("updates too long, getting difference ...");
    m_user_agent.get_difference(false, nullptr);
}

void updater::work_update_short(const tl_ds_updates* DS_U, update_mode mode)
{
    if (m_user_agent.is_diff_locked()) {
        return;
    }

    work_update(DS_U->update, nullptr, mode);
}

void updater::work_update_short_sent_message(const tl_ds_updates* DS_U,
        const std::shared_ptr<void>& extra, update_mode mode)
{
    if (mode == update_mode::check_and_update_consistency
            && DS_U->pts
            && !check_pts_diff(DS_LVAL(DS_U->pts), DS_LVAL(DS_U->pts_count))) {
        return;
    }

    if (auto old_message = std::static_pointer_cast<message>(extra)) {
        if (auto new_message = message::create_from_short_update(m_user_agent.our_id(), DS_U)) {
            if (new_message->media()) {
                old_message->set_media(new_message->media());
                m_user_agent.callback()->update_messages({old_message});
            }
            m_user_agent.callback()->message_sent(old_message->id(), new_message->id(), new_message->date(), old_message->to_id());
        }
    }

    if (mode != update_mode::check_and_update_consistency) {
        assert(mode == update_mode::dont_check_and_update_consistency);
        return;
    }

    if (DS_U->pts) {
        m_user_agent.set_pts(DS_LVAL(DS_U->pts));
    }
}

void updater::work_any_updates(const tl_ds_updates* DS_U, const std::shared_ptr<void>& extra, update_mode mode)
{
    if (m_user_agent.is_diff_locked()) {
        return;
    }

    switch (DS_U->magic) {
    case CODE_updates_too_long:
        work_updates_too_long(DS_U, mode);
        return;
    case CODE_update_short_message:
        work_update_short_message(DS_U, mode);
        return;
    case CODE_update_short_chat_message:
        work_update_short_chat_message(DS_U, mode);
        return;
    case CODE_update_short:
        work_update_short(DS_U, mode);
        return;
    case CODE_updates_combined:
        work_updates_combined(DS_U, mode);
        return;
    case CODE_updates:
        work_updates(DS_U, extra, mode);
        return;
    case CODE_update_short_sent_message:
        work_update_short_sent_message(DS_U, extra, mode);
        return;
    default:
        assert(false);
    }
}

void updater::work_any_updates(tgl_in_buffer* in)
{
    paramed_type type = TYPE_TO_PARAM(updates);
    tl_ds_updates* DS_U = fetch_ds_type_updates(in, &type);
    if (!DS_U) {
        TGL_WARNING("failed to fetch updates from response from the server, likely corrupt data");
        return;
    }

    work_any_updates(DS_U, nullptr, update_mode::check_and_update_consistency);
    free_ds_type_updates(DS_U, &type);
}

void updater::work_encrypted_message(const tl_ds_encrypted_message* DS_EM)
{
    std::shared_ptr<secret_chat> sc = m_user_agent.secret_chat_for_id(DS_LVAL(DS_EM->chat_id));
    if (!sc || sc->state() != tgl_secret_chat_state::ok) {
        TGL_WARNING("encrypted message to unknown chat, dropping");
        return;
    }

    sc->imbue_encrypted_message(DS_EM);
}

}
}
