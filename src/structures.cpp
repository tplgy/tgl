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

#include "structures.h"

#include "auto/auto.h"
#include "auto/auto-skip.h"
#include "auto/auto-types.h"
#include "auto/auto-free-ds.h"
#include "auto/auto-fetch-ds.h"
#include "crypto/tgl_crypto_aes.h"
#include "crypto/tgl_crypto_bn.h"
#include "crypto/tgl_crypto_sha.h"
#include "mtproto_client.h"
#include "mtproto-common.h"
#include "queries.h"
#include "queries-encrypted.h"
#include "tgl/tgl.h"
#include "tgl/tgl_bot.h"
#include "tgl/tgl_queries.h"
#include "tgl/tgl_secret_chat.h"
#include "tgl/tgl_update_callback.h"
#include "tgl/tgl_user.h"
#include "tgl_secret_chat_private.h"
#include "updates.h"

#include <algorithm>
#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>

enum tgl_typing_status tglf_fetch_typing(const tl_ds_send_message_action* DS_SMA)
{
    if (!DS_SMA) {
        return tgl_typing_status::none;
    }
    switch (DS_SMA->magic) {
    case CODE_send_message_typing_action:
        return tgl_typing_status::typing;
    case CODE_send_message_cancel_action:
        return tgl_typing_status::cancel;
    case CODE_send_message_record_video_action:
        return tgl_typing_status::record_video;
    case CODE_send_message_upload_video_action:
        return tgl_typing_status::upload_video;
    case CODE_send_message_record_audio_action:
        return tgl_typing_status::record_audio;
    case CODE_send_message_upload_audio_action:
        return tgl_typing_status::upload_audio;
    case CODE_send_message_upload_photo_action:
        return tgl_typing_status::upload_photo;
    case CODE_send_message_upload_document_action:
        return tgl_typing_status::upload_document;
    case CODE_send_message_geo_location_action:
        return tgl_typing_status::geo;
    case CODE_send_message_choose_contact_action:
        return tgl_typing_status::choose_contact;
    default:
        assert(false);
        return tgl_typing_status::none;
    }
}

/*enum tgl_typing_status tglf_fetch_typing(void)
{
    struct paramed_type type = TYPE_TO_PARAM(send_message_action);
    struct tl_ds_send_message_action* DS_SMA = fetch_ds_type_send_message_action(&type);
    enum tgl_typing_status res = tglf_fetch_typing_new(DS_SMA);
    free_ds_type_send_message_action(DS_SMA, &type);
    return res;
}*/

/* {{{ Fetch */

tgl_peer_id_t tglf_fetch_peer_id(const tl_ds_peer* DS_P)
{
    switch (DS_P->magic) {
    case CODE_peer_user:
        return tgl_peer_id_t(tgl_peer_type::user, DS_LVAL(DS_P->user_id));
    case CODE_peer_chat:
        return tgl_peer_id_t(tgl_peer_type::chat, DS_LVAL(DS_P->chat_id));
    case CODE_peer_channel:
        return tgl_peer_id_t(tgl_peer_type::channel, DS_LVAL(DS_P->channel_id));
    default:
        assert(false);
        exit(2);
    }
}

tgl_file_location tglf_fetch_file_location(const tl_ds_file_location* DS_FL)
{
    tgl_file_location location;

    if (!DS_FL) {
        return location;
    }

    location.set_dc(DS_LVAL(DS_FL->dc_id));
    location.set_volume(DS_LVAL(DS_FL->volume_id));
    location.set_local_id(DS_LVAL(DS_FL->local_id));
    location.set_secret(DS_LVAL(DS_FL->secret));

    return location;
}

tgl_user_status tglf_fetch_user_status(const tl_ds_user_status* DS_US)
{
    tgl_user_status new_status;
    if (!DS_US) { return new_status; }
    switch (DS_US->magic) {
    case CODE_user_status_empty:
        new_status.online = tgl_user_online_status::unknown;
        new_status.when = 0;
        break;
    case CODE_user_status_online:
        new_status.online = tgl_user_online_status::online;
        new_status.when = DS_LVAL(DS_US->expires);
        break;
    case CODE_user_status_offline:
        new_status.online = tgl_user_online_status::offline;
        new_status.when = DS_LVAL(DS_US->was_online);
        break;
    case CODE_user_status_recently:
        new_status.online = tgl_user_online_status::recent;
        break;
    case CODE_user_status_last_week:
        new_status.online = tgl_user_online_status::last_week;
        break;
    case CODE_user_status_last_month:
        new_status.online = tgl_user_online_status::last_month;
        break;
    default:
        assert(false);
    }
    return new_status;
}

std::shared_ptr<tgl_user> tglf_fetch_alloc_user(const tl_ds_user* DS_U, bool invoke_callback)
{
    if (!DS_U) {
        return nullptr;
    }

    if (DS_U->magic == CODE_user_empty) {
      return nullptr;
    }

    tgl_input_peer_t user_id(tgl_peer_type::user, DS_LVAL(DS_U->id), DS_LVAL(DS_U->access_hash));

    std::shared_ptr<tgl_user> user = std::make_shared<tgl_user>();
    user->id = user_id;

    //int flags = user->flags;
    int32_t flags = DS_LVAL(DS_U->flags);

    if (flags & (1 << 10)) {
        tgl_state::instance()->set_our_id(user_id.peer_id);
        user->set_self(true);
    } else {
        user->set_self(false);
    }

    user->set_contact(flags & (1 << 11));
    user->set_mutual_contact(flags & (1 << 12));
    user->set_bot(flags & (1 << 14));

    /*
    if (DS_LVAL(DS_U->flags) & (1 << 15)) {
        flags |= TGLUF_BOT_FULL_ACCESS;
    }

    if (DS_LVAL(DS_U->flags) & (1 << 16)) {
        flags |= TGLUF_BOT_NO_GROUPS;
    }*/

    user->set_official(flags & (1 << 17));

    user->firstname = DS_STDSTR(DS_U->first_name);
    user->lastname = DS_STDSTR(DS_U->last_name);
    user->username = DS_STDSTR(DS_U->username);
    user->phone = DS_STDSTR(DS_U->phone);
    user->status = tglf_fetch_user_status(DS_U->status);

    if (DS_LVAL(DS_U->flags) & (1 << 13)) {
        tgl_state::instance()->callback()->user_deleted(user_id.peer_id);
        return user;
    } else {
        if (invoke_callback) {
            tgl_state::instance()->callback()->new_user(user);
        }

        if (DS_U->photo && invoke_callback) {
            tgl_file_location photo_big = tglf_fetch_file_location(DS_U->photo->photo_big);
            tgl_file_location photo_small = tglf_fetch_file_location(DS_U->photo->photo_small);
            tgl_state::instance()->callback()->avatar_update(user_id.peer_id, user_id.peer_type, photo_small, photo_big);
        }
        return user;
    }
}

std::shared_ptr<tgl_user> tglf_fetch_alloc_user_full(const tl_ds_user_full* DS_UF)
{
    if (!DS_UF) {
        return nullptr;
    }

    auto user = tglf_fetch_alloc_user(DS_UF->user);
    if (!user) {
        return nullptr;
    }

    user->set_blocked(DS_BVAL(DS_UF->blocked));

    if (DS_UF->user->photo) {
        tgl_file_location photo_big = tglf_fetch_file_location(DS_UF->user->photo->photo_big);
        tgl_file_location photo_small = tglf_fetch_file_location(DS_UF->user->photo->photo_small);
        tgl_state::instance()->callback()->avatar_update(user->id.peer_id, user->id.peer_type,photo_small, photo_big);
    }

    return user;
}

inline static void str_to_256(unsigned char* dst, const char* src, int src_len)
{
    if (src_len >= 256) {
        memcpy(dst, src + src_len - 256, 256);
    } else {
        memset(dst, 0, 256 - src_len);
        memcpy(dst + 256 - src_len, src, src_len);
    }
}

inline static void str_to_32(unsigned char* dst, const char* src, int src_len)
{
    if (src_len >= 32) {
        memcpy(dst, src + src_len - 32, 32);
    } else {
        memset(dst, 0, 32 - src_len);
        memcpy(dst + 32 - src_len, src, src_len);
    }
}

std::shared_ptr<tgl_secret_chat> tglf_fetch_alloc_encrypted_chat(const tl_ds_encrypted_chat* DS_EC)
{
    TGL_DEBUG("fetching secret chat from " << DS_EC);
    if (!DS_EC) {
        return nullptr;
    }

    if (DS_EC->magic == CODE_encrypted_chat_empty) {
        TGL_DEBUG("empty secret chat found, discarding");
        return nullptr;
    }

    tgl_input_peer_t chat_id(tgl_peer_type::enc_chat, DS_LVAL(DS_EC->id), DS_LVAL(DS_EC->access_hash));

    std::shared_ptr<tgl_secret_chat> secret_chat = tgl_state::instance()->secret_chat_for_id(chat_id);

    bool is_new = false;
    if (!secret_chat) {
        int admin_id = DS_LVAL(DS_EC->id);

        if (!admin_id) {
            // It must be a secret chat which is encryptedChatDiscarded#13d6dd27.
            // For a discarded secret chat which is not on our side either, we do nothing.
            TGL_DEBUG("discarded secret chat " << chat_id.peer_id << " found, doing nothing");
            return nullptr;
        }

        if (admin_id != tgl_state::instance()->our_id().peer_id) {
            // It must be a new secret chat requested from the peer.
            secret_chat = tgl_state::instance()->create_secret_chat(chat_id, DS_LVAL(DS_EC->participant_id));
            is_new = true;
            TGL_DEBUG("new secret chat " << chat_id.peer_id << " found");
        }
    }

    if (!secret_chat) {
        TGL_DEBUG("no secret chat found or created for id " << chat_id.peer_id);
        return nullptr;
    }

    if (DS_EC->magic == CODE_encrypted_chat_discarded) {
        if (is_new) {
            TGL_DEBUG("this is a new scret chat " << chat_id.peer_id << " but has been discarded, doing nothing");
            return nullptr;
        }

        TGL_DEBUG("discarded secret chat " << chat_id.peer_id << " found, setting it to deleted state");
        tgl_secret_chat_deleted(secret_chat);
        return secret_chat;
    }

    unsigned char g_key[256];
    memset(g_key, 0, sizeof(g_key));
    if (is_new) {
        if (DS_EC->magic != CODE_encrypted_chat_requested) {
            TGL_DEBUG("new secret chat " << chat_id.peer_id << " but not in requested state");
            return secret_chat;
        }
        TGL_DEBUG("updating new secret chat " << chat_id.peer_id);

        str_to_256(g_key, DS_STR(DS_EC->g_a));

        int32_t user_id = DS_LVAL(DS_EC->participant_id) + DS_LVAL(DS_EC->admin_id) - tgl_state::instance()->our_id().peer_id;
        if (DS_EC->access_hash) {
            secret_chat->private_facet()->set_access_hash(*(DS_EC->access_hash));
        }
        if (DS_EC->date) {
            secret_chat->private_facet()->set_date(*(DS_EC->date));
        }
        if (DS_EC->admin_id) {
            secret_chat->private_facet()->set_admin_id(*(DS_EC->admin_id));
        }
        secret_chat->private_facet()->set_user_id(user_id);
        secret_chat->private_facet()->set_g_key(g_key, sizeof(g_key));
        secret_chat->private_facet()->set_state(tgl_secret_chat_state::request);
    } else {
        TGL_DEBUG("updating existing secret chat " << chat_id.peer_id);
        const unsigned char* g_key_ptr = nullptr;
        tgl_secret_chat_state state;
        if (DS_EC->magic == CODE_encrypted_chat_waiting) {
            state = tgl_secret_chat_state::waiting;
        } else {
            state = tgl_secret_chat_state::ok;
            str_to_256(g_key, DS_STR(DS_EC->g_a_or_b));
            g_key_ptr = g_key;
            secret_chat->private_facet()->set_temp_key_fingerprint(DS_LVAL(DS_EC->key_fingerprint));
        }
        if (DS_EC->access_hash) {
            secret_chat->private_facet()->set_access_hash(*(DS_EC->access_hash));
        }
        if (DS_EC->date) {
            secret_chat->private_facet()->set_date(*(DS_EC->date));
        }
        secret_chat->private_facet()->set_g_key(g_key, sizeof(g_key));
        secret_chat->private_facet()->set_state(state);
    }

    return secret_chat;
}

static void update_chat_flags(const std::shared_ptr<tgl_chat>& chat, int32_t flags)
{
    chat->creator = flags & 1;
    chat->kicked = flags & 2;
    chat->left = flags & 4;
    chat->admins_enabled = flags & 8;
    chat->admin = flags & 16;
    chat->deactivated = flags & 32;
}

static void update_channel_flags(const std::shared_ptr<tgl_channel>& channel, int32_t flags)
{
    channel->creator = flags & 1;
    channel->kicked = flags & 2;
    channel->left = flags & 4;
    channel->verified = flags & 7;
    channel->editor = flags & 8;
    channel->restricted = flags & 9;
    channel->moderator = flags & 16;
    channel->broadcast = flags & 32;
    channel->official = flags & 128;
    channel->megagroup = flags & 256;
}

std::shared_ptr<tgl_chat> tglf_fetch_alloc_chat(const tl_ds_chat* DS_C, bool invoke_callback)
{
    if (!DS_C) {
        return nullptr;
    }

    if (DS_C->magic == CODE_chat_empty) {
        return nullptr;
    }

    if (DS_C->magic == CODE_channel || DS_C->magic == CODE_channel_forbidden) {
        return tglf_fetch_alloc_channel(DS_C, invoke_callback);
    }

    tgl_input_peer_t chat_id(tgl_peer_type::chat, DS_LVAL(DS_C->id), DS_LVAL(DS_C->access_hash));

    std::shared_ptr<tgl_chat> chat = std::make_shared<tgl_chat>();
    chat->id = chat_id;
    chat->forbidden = DS_C->magic == CODE_chat_forbidden;

    update_chat_flags(chat, DS_LVAL(DS_C->flags));

    chat->editor = DS_BOOL(DS_C->editor);
    chat->moderator = DS_BOOL(DS_C->moderator);
    chat->megagroup = DS_BOOL(DS_C->megagroup);
    chat->verified = DS_BOOL(DS_C->verified);
    chat->restricted = DS_BOOL(DS_C->restricted);

    if (DS_C->photo) {
        chat->photo_big = tglf_fetch_file_location(DS_C->photo->photo_big);
        chat->photo_small = tglf_fetch_file_location(DS_C->photo->photo_small);
    }

    chat->title = DS_STDSTR(DS_C->title);
    chat->username = DS_STDSTR(DS_C->username);
    chat->participants_count = DS_LVAL(DS_C->participants_count);
    chat->date = DS_LVAL(DS_C->date);

    if (invoke_callback) {
        tgl_state::instance()->callback()->chat_update(chat);
        tgl_state::instance()->callback()->avatar_update(chat->id.peer_id, chat->id.peer_type, chat->photo_big, chat->photo_small);
    }

    return chat;
}

std::shared_ptr<tgl_chat> tglf_fetch_alloc_chat_full(const tl_ds_messages_chat_full* DS_MCF)
{
    if (!DS_MCF) {
        return nullptr;
    }

    if (DS_MCF->full_chat->magic == CODE_channel_full) {
        return tglf_fetch_alloc_channel_full(DS_MCF);
    }

    if (DS_MCF->users) {
        for (int i = 0; i < DS_LVAL(DS_MCF->users->cnt); i++) {
            tglf_fetch_alloc_user(DS_MCF->users->data[i]);
        }
    }

    if (DS_MCF->chats) {
        for (int i = 0; i < DS_LVAL(DS_MCF->chats->cnt); i++) {
            tglf_fetch_alloc_chat(DS_MCF->chats->data[i]);
        }
    }

    const tl_ds_chat_full* DS_CF = DS_MCF->full_chat;

#if 0
    if (DS_CF->bot_info) {
      int n = DS_LVAL(DS_CF->bot_info->cnt);
      for (int i = 0; i < n; i++) {
      struct tl_ds_bot_info* DS_BI = DS_CF->bot_info->data[i];

      tgl_peer_id_t peer_id = tgl_peer_id_t(tgl_peer_type::user, DS_LVAL(DS_BI->user_id));
        if (P && (P->flags & TGLCF_CREATED)) {
          bl_do_user(tgl_get_peer_id(P->id),
              NULL,
              NULL, 0,
              NULL, 0,
              NULL, 0,
              NULL, 0,
              NULL,
              NULL,
              NULL, NULL,
              DS_BI,
              TGL_FLAGS_UNCHANGED
              );
        }
      }
    }
#endif

    tgl_input_peer_t chat_id(tgl_peer_type::chat, DS_LVAL(DS_CF->id), 0);
    std::shared_ptr<tgl_chat> chat = std::make_shared<tgl_chat>();
    chat->id = chat_id;

    if (DS_CF->chat_photo && DS_CF->chat_photo->sizes && *DS_CF->chat_photo->sizes->cnt > 1) {
        chat->photo_big = tglf_fetch_file_location(DS_CF->chat_photo->sizes->data[1]->location);
    }
    if (DS_CF->chat_photo && DS_CF->chat_photo->sizes && *DS_CF->chat_photo->sizes->cnt > 0) {
        chat->photo_small = tglf_fetch_file_location(DS_CF->chat_photo->sizes->data[0]->location);
    }

    if (DS_CF->participants && DS_CF->participants->participants) {
        std::vector<std::shared_ptr<tgl_chat_participant>> participants;
        for (int i = 0; i < DS_LVAL(DS_CF->participants->participants->cnt); ++i) {
            bool admin = false;
            bool creator = false;
            if (DS_CF->participants->participants->data[i]->magic == CODE_chat_participant_admin) {
                admin = true;
            } else if (DS_CF->participants->participants->data[i]->magic == CODE_chat_participant_creator) {
                creator = true;
                admin = true;
            }
            auto participant = std::make_shared<tgl_chat_participant>();
            participant->user_id = DS_LVAL(DS_CF->participants->participants->data[i]->user_id);
            participant->inviter_id = DS_LVAL(DS_CF->participants->participants->data[i]->inviter_id);
            participant->date = DS_LVAL(DS_CF->participants->participants->data[i]->date);
            participant->is_admin = admin;
            participant->is_creator = creator;
            participants.push_back(participant);
        }
        if (participants.size()) {
            tgl_state::instance()->callback()->chat_update_participants(chat_id.peer_id, participants);
        }
    }
    //TODO update users

    return chat;
}

std::shared_ptr<tgl_channel> tglf_fetch_alloc_channel(const tl_ds_chat* DS_C, bool invoke_callback)
{
    if (!DS_C) {
        return nullptr;
    }

    tgl_input_peer_t chat_id(tgl_peer_type::channel, DS_LVAL(DS_C->id), DS_LVAL(DS_C->access_hash));

    std::shared_ptr<tgl_channel> channel = std::make_shared<tgl_channel>();
    channel->id = chat_id;
    channel->forbidden = DS_C->magic == CODE_channel_forbidden;

    update_channel_flags(channel, DS_LVAL(DS_C->flags));

    if (DS_C->photo) {
        channel->photo_big = tglf_fetch_file_location(DS_C->photo->photo_big);
        channel->photo_small = tglf_fetch_file_location(DS_C->photo->photo_small);
    }

    channel->title = DS_STDSTR(DS_C->title);
    channel->username = DS_STDSTR(DS_C->username);
    channel->date = DS_LVAL(DS_C->date);

    if (invoke_callback) {
        tgl_state::instance()->callback()->channel_update(channel);
        tgl_state::instance()->callback()->avatar_update(channel->id.peer_id, channel->id.peer_type, channel->photo_big, channel->photo_small);
    }

    return channel;
}

std::shared_ptr<tgl_channel> tglf_fetch_alloc_channel_full(const tl_ds_messages_chat_full* DS_MCF)
{
    if (!DS_MCF) {
        return nullptr;
    }

    if (DS_MCF->users) {
        for (int i = 0; i < DS_LVAL(DS_MCF->users->cnt); i++) {
            tglf_fetch_alloc_user(DS_MCF->users->data[i]);
        }
    }

    if (DS_MCF->chats) {
        for (int i = 0; i < DS_LVAL(DS_MCF->chats->cnt); i++) {
            tglf_fetch_alloc_chat(DS_MCF->chats->data[i]);
        }
    }

    const tl_ds_chat_full* DS_CF = DS_MCF->full_chat;

    tgl_input_peer_t channel_id(tgl_peer_type::channel, DS_LVAL(DS_CF->id), 0); // FIXME: what about access_hash?

    std::shared_ptr<tgl_channel> channel = std::make_shared<tgl_channel>();
    channel->id = channel_id;
    channel->about = DS_STDSTR(DS_CF->about);
    channel->participants_count = DS_LVAL(DS_CF->participants_count);

    if (DS_CF->chat_photo && DS_CF->chat_photo->sizes && *DS_CF->chat_photo->sizes->cnt > 1) {
        channel->photo_big = tglf_fetch_file_location(DS_CF->chat_photo->sizes->data[1]->location);
    }
    if (DS_CF->chat_photo && DS_CF->chat_photo->sizes && *DS_CF->chat_photo->sizes->cnt > 0) {
        channel->photo_small = tglf_fetch_file_location(DS_CF->chat_photo->sizes->data[0]->location);
    }

    tgl_state::instance()->callback()->channel_update_info(channel->id.peer_id, channel->about, channel->participants_count);

    return channel;
}

static std::shared_ptr<tgl_photo_size> tglf_fetch_photo_size(struct tl_ds_photo_size* DS_PS)
{
    auto photo_size = std::make_shared<tgl_photo_size>();

    photo_size->type = DS_STDSTR(DS_PS->type);
    photo_size->w = DS_LVAL(DS_PS->w);
    photo_size->h = DS_LVAL(DS_PS->h);
    photo_size->size = DS_LVAL(DS_PS->size);
    if (DS_PS->bytes) {
        photo_size->size = DS_PS->bytes->len;
    }

    photo_size->loc = tglf_fetch_file_location(DS_PS->location);

    return photo_size;
}

void tglf_fetch_geo(tgl_geo* G, const tl_ds_geo_point* DS_GP)
{
    G->longitude = DS_LVAL(DS_GP->longitude);
    G->latitude = DS_LVAL(DS_GP->latitude);
}

std::shared_ptr<tgl_photo> tglf_fetch_alloc_photo(const tl_ds_photo* DS_P)
{
    if (!DS_P) {
        return nullptr;
    }

    if (DS_P->magic == CODE_photo_empty) {
        return nullptr;
    }

    auto photo = std::make_shared<tgl_photo>();
    photo->id = DS_LVAL(DS_P->id);
    //photo->refcnt = 1;

    photo->access_hash = DS_LVAL(DS_P->access_hash);
    //photo->user_id = DS_LVAL(DS_P->user_id);
    photo->date = DS_LVAL(DS_P->date);
    //photo->caption = NULL;//DS_STR_DUP(DS_P->caption);
    /*if (DS_P->geo) {
      tglf_fetch_geo(&P->geo, DS_P->geo);
    }*/

    int sizes_num = DS_LVAL(DS_P->sizes->cnt);
    photo->sizes.resize(sizes_num);
    for (int i = 0; i < sizes_num; ++i) {
        photo->sizes[i] = tglf_fetch_photo_size(DS_P->sizes->data[i]);
    }

    return photo;
}

std::shared_ptr<tgl_document> tglf_fetch_alloc_video(const tl_ds_video* DS_V)
{
    if (!DS_V) {
        return nullptr;
    }

    if (DS_V->magic == CODE_video_empty) {
        return nullptr;
    }

    auto document = std::make_shared<tgl_document>();
    document->id = DS_LVAL(DS_V->id);

    document->type = tgl_document_type::video;

    document->access_hash = DS_LVAL(DS_V->access_hash);
    //document->user_id = DS_LVAL(DS_V->user_id);
    document->date = DS_LVAL(DS_V->date);
    //document->caption = NULL;//DS_STR_DUP(DS_V->caption);
    document->duration = DS_LVAL(DS_V->duration);
    document->mime_type = DS_STDSTR(DS_V->mime_type);
    if (document->mime_type.empty()) {
        document->mime_type = "video/";
    }
    document->size = DS_LVAL(DS_V->size);

    if (DS_V->thumb && DS_V->thumb->magic != CODE_photo_size_empty) {
        document->thumb = tglf_fetch_photo_size(DS_V->thumb);
    }

    document->dc_id = DS_LVAL(DS_V->dc_id);
    document->w = DS_LVAL(DS_V->w);
    document->h = DS_LVAL(DS_V->h);

    return document;
}

std::shared_ptr<tgl_document> tglf_fetch_alloc_audio(const tl_ds_audio* DS_A)
{
    if (!DS_A) {
        return nullptr;
    }

    if (DS_A->magic == CODE_audio_empty) {
        return nullptr;
    }

    auto document = std::make_shared<tgl_document>();
    document->id = DS_LVAL(DS_A->id);
    document->type = tgl_document_type::audio;

    document->access_hash = DS_LVAL(DS_A->access_hash);
    //document->user_id = DS_LVAL(DS_A->user_id);
    document->date = DS_LVAL(DS_A->date);
    document->duration = DS_LVAL(DS_A->duration);
    document->mime_type = DS_STDSTR(DS_A->mime_type);
    document->size = DS_LVAL(DS_A->size);
    document->dc_id = DS_LVAL(DS_A->dc_id);

    return document;
}

void tglf_fetch_document_attribute(const std::shared_ptr<tgl_document>& document, const tl_ds_document_attribute* DS_DA)
{
    switch (DS_DA->magic) {
    case CODE_document_attribute_image_size:
        document->type = tgl_document_type::image;
        document->w = DS_LVAL(DS_DA->w);
        document->h = DS_LVAL(DS_DA->h);
        return;
    case CODE_document_attribute_animated:
        document->is_animated = true;
        return;
    case CODE_document_attribute_sticker:
        document->type = tgl_document_type::sticker;
        document->caption = DS_STDSTR(DS_DA->alt);
        return;
    case CODE_document_attribute_video:
        document->type = tgl_document_type::video;
        document->duration = DS_LVAL(DS_DA->duration);
        document->w = DS_LVAL(DS_DA->w);
        document->h = DS_LVAL(DS_DA->h);
        return;
    case CODE_document_attribute_audio:
        document->type = tgl_document_type::audio;
        document->duration = DS_LVAL(DS_DA->duration);
        return;
    case CODE_document_attribute_filename:
        document->file_name = DS_STDSTR(DS_DA->file_name);
        return;
    default:
        assert(false);
    }
}

std::shared_ptr<tgl_document> tglf_fetch_alloc_document(const tl_ds_document* DS_D)
{
    if (!DS_D) {
        return nullptr;
    }

    if (DS_D->magic == CODE_document_empty) {
        return nullptr;
    }

    auto document = std::make_shared<tgl_document>();
    document->id = DS_LVAL(DS_D->id);
    document->access_hash = DS_LVAL(DS_D->access_hash);
    //D->user_id = DS_LVAL(DS_D->user_id);
    document->date = DS_LVAL(DS_D->date);
    document->mime_type = DS_STDSTR(DS_D->mime_type);
    document->size = DS_LVAL(DS_D->size);
    document->dc_id = DS_LVAL(DS_D->dc_id);

    if (DS_D->thumb && DS_D->thumb->magic != CODE_photo_size_empty) {
        document->thumb = tglf_fetch_photo_size(DS_D->thumb);
    }

    if (DS_D->attributes) {
        for (int i = 0; i < DS_LVAL(DS_D->attributes->cnt); i++) {
            tglf_fetch_document_attribute(document, DS_D->attributes->data[i]);
        }
    }

    return document;
}

static std::shared_ptr<tgl_webpage> tglf_fetch_alloc_webpage(const tl_ds_web_page* DS_W)
{
    if (!DS_W) {
        return nullptr;
    }

    auto webpage = std::make_shared<tgl_webpage>();
    webpage->id = DS_LVAL(DS_W->id);
    //webpage->refcnt = 1;

    webpage->url = DS_STDSTR(DS_W->url);
    webpage->display_url = DS_STDSTR(DS_W->display_url);
    webpage->type = DS_STDSTR(DS_W->type);
    webpage->title = DS_W->title ? DS_STDSTR(DS_W->title) : (DS_W->site_name ? DS_STDSTR(DS_W->site_name) : "");
    webpage->photo = tglf_fetch_alloc_photo(DS_W->photo);
    webpage->description = DS_STDSTR(DS_W->description);
    webpage->embed_url = DS_STDSTR(DS_W->embed_url);
    webpage->embed_type = DS_STDSTR(DS_W->embed_type);
    webpage->embed_width = DS_LVAL(DS_W->embed_width);
    webpage->embed_height = DS_LVAL(DS_W->embed_height);
    webpage->duration = DS_LVAL(DS_W->duration);
    webpage->author = DS_STDSTR(DS_W->author);

    return webpage;
}

std::shared_ptr<tgl_message_action> tglf_fetch_message_action(const tl_ds_message_action* DS_MA)
{
    if (!DS_MA) {
        return nullptr;
    }

    switch (DS_MA->magic) {
    case CODE_message_action_empty:
        return std::make_shared<tgl_message_action_none>();
    /*case CODE_message_action_geo_chat_create:
      {
        M->type = tgl_message_action_geo_chat_create;
        assert(false);
      }
      break;*/
    /*case CODE_message_action_geo_chat_checkin:
      M->type = tgl_message_action_geo_chat_checkin;
      break;*/
    case CODE_message_action_chat_create:
    {
        auto action = std::make_shared<tgl_message_action_chat_create>();
        action->title = DS_STDSTR(DS_MA->title);
        action->users.resize(DS_LVAL(DS_MA->users->cnt));
        for (size_t i = 0; i < action->users.size(); ++i) {
            action->users[i] = DS_LVAL(DS_MA->users->data[i]);
        }
        return action;
    }
    case CODE_message_action_chat_edit_title:
    {
        auto action = std::make_shared<tgl_message_action_chat_edit_title>();
        action->new_title = DS_STDSTR(DS_MA->title);
        return action;
    }
    case CODE_message_action_chat_edit_photo:
        return std::make_shared<tgl_message_action_chat_edit_photo>(tglf_fetch_alloc_photo(DS_MA->photo));
    case CODE_message_action_chat_delete_photo:
        return std::make_shared<tgl_message_action_chat_delete_photo>();
    case CODE_message_action_chat_add_user:
    {
        auto action = std::make_shared<tgl_message_action_chat_add_users>();
        action->users.resize(DS_LVAL(DS_MA->users->cnt));
        for (size_t i = 0; i < action->users.size(); ++i) {
            action->users[i] = DS_LVAL(DS_MA->users->data[i]);
        }
        return action;
    }
    case CODE_message_action_chat_delete_user:
        return std::make_shared<tgl_message_action_chat_delete_user>(DS_LVAL(DS_MA->user_id));
    case CODE_message_action_chat_joined_by_link:
        return std::make_shared<tgl_message_action_chat_add_user_by_link>(DS_LVAL(DS_MA->inviter_id));
    case CODE_message_action_channel_create:
    {
        auto action = std::make_shared<tgl_message_action_channel_create>();
        action->title = DS_STDSTR(DS_MA->title);
    }
    case CODE_message_action_chat_migrate_to:
        return std::make_shared<tgl_message_action_chat_migrate_to>();
    case CODE_message_action_channel_migrate_from:
    {
        auto action = std::make_shared<tgl_message_action_channel_migrate_from>();
        action->title = DS_STDSTR(DS_MA->title);
        return action;
    }
    default:
        assert(false);
        return nullptr;
    }
}

std::shared_ptr<tgl_message> tglf_fetch_alloc_message_short(const tl_ds_updates* DS_U)
{
    tgl_peer_id_t peer_id = tgl_peer_id_t(tgl_peer_type::user, DS_LVAL(DS_U->user_id));

    int64_t message_id = DS_LVAL(DS_U->id);
    int32_t flags = DS_LVAL(DS_U->flags);

//    struct tl_ds_message_media A;
//    A.magic = CODE_message_media_empty;

    tgl_peer_id_t our_id = tgl_state::instance()->our_id();

    tgl_peer_id_t fwd_from_id;
    if (DS_U->fwd_from_id) {
        fwd_from_id = tglf_fetch_peer_id(DS_U->fwd_from_id);
    } else {
        fwd_from_id = tgl_peer_id_t(tgl_peer_type::user, 0);
    }

    int64_t fwd_date = DS_LVAL(DS_U->fwd_date);
    int64_t date = DS_LVAL(DS_U->date);
    std::shared_ptr<tgl_message> msg = std::make_shared<tgl_message>(message_id,
            (flags & 2) ? our_id : peer_id,
            (flags & 2) ? tgl_input_peer_t(peer_id.peer_type, peer_id.peer_id, 0) : tgl_input_peer_t(our_id.peer_type, our_id.peer_id, 0),
            DS_U->fwd_from_id ? &fwd_from_id : NULL,
            &fwd_date,
            &date,
            DS_STDSTR(DS_U->message),
            DS_U->media,
            nullptr,
            DS_LVAL(DS_U->reply_to_msg_id),
            nullptr);
    msg->set_unread(flags&1).set_outgoing(flags&2).set_mention(flags&16);
    return msg;
}

std::shared_ptr<tgl_message> tglf_fetch_alloc_message_short_chat(const tl_ds_updates* DS_U)
{
    tgl_peer_id_t from_id = tgl_peer_id_t(tgl_peer_type::user, DS_LVAL(DS_U->from_id));
    tgl_input_peer_t to_id = tgl_input_peer_t(tgl_peer_type::chat, DS_LVAL(DS_U->chat_id), 0);

    int64_t message_id = DS_LVAL(DS_U->id);
    int32_t flags = DS_LVAL(DS_U->flags);

    struct tl_ds_message_media media;
    media.magic = CODE_message_media_empty;

    tgl_peer_id_t fwd_from_id;
    if (DS_U->fwd_from_id) {
        fwd_from_id = tglf_fetch_peer_id(DS_U->fwd_from_id);
    } else {
        fwd_from_id = tgl_peer_id_t(tgl_peer_type::user, 0);
    }

    int64_t fwd_date = DS_LVAL(DS_U->fwd_date);
    int64_t date = DS_LVAL(DS_U->date);
    auto message = std::make_shared<tgl_message>(message_id,
            from_id,
            to_id,
            DS_U->fwd_from_id ? &fwd_from_id : nullptr,
            &fwd_date,
            &date,
            DS_STDSTR(DS_U->message),
            &media,
            nullptr,
            DS_LVAL(DS_U->reply_to_msg_id),
            nullptr);
    message->set_unread(flags&1).set_outgoing(flags&2).set_mention(flags&16);
    return message;
}


std::shared_ptr<tgl_message_media> tglf_fetch_message_media(const tl_ds_message_media* DS_MM)
{
    if (!DS_MM) {
        return nullptr;
    }

    switch (DS_MM->magic) {
    case CODE_message_media_empty:
        return std::make_shared<tgl_message_media_none>();
    case CODE_message_media_photo:
    case CODE_message_media_photo_l27:
    {
        auto media = std::make_shared<tgl_message_media_photo>();
        media->photo = tglf_fetch_alloc_photo(DS_MM->photo);
        media->caption = DS_STDSTR(DS_MM->caption);
        return media;
    }
    case CODE_message_media_video:
    case CODE_message_media_video_l27:
    {
        auto media = std::make_shared<tgl_message_media_video>();
        media->document = tglf_fetch_alloc_video(DS_MM->video);
        media->caption = DS_STDSTR(DS_MM->caption);
        return media;
    }
    case CODE_message_media_audio:
    {
        auto media = std::make_shared<tgl_message_media_audio>();
        media->document = tglf_fetch_alloc_audio(DS_MM->audio);
        media->caption = DS_STDSTR(DS_MM->caption);
        return media;
    }
    case CODE_message_media_document:
    {
        auto media = std::make_shared<tgl_message_media_document>();
        media->document = tglf_fetch_alloc_document(DS_MM->document);
        media->caption = DS_STDSTR(DS_MM->caption);
        return media;
    }
    case CODE_message_media_geo:
    {
        auto media = std::make_shared<tgl_message_media_geo>();
        tglf_fetch_geo(&media->geo, DS_MM->geo);
        return media;
    }
    case CODE_message_media_contact:
    {
        auto media = std::make_shared<tgl_message_media_contact>();
        media->phone = DS_STDSTR(DS_MM->phone_number);
        media->first_name = DS_STDSTR(DS_MM->first_name);
        media->last_name = DS_STDSTR(DS_MM->last_name);
        media->user_id = DS_LVAL(DS_MM->user_id);
        return media;
    }
    case CODE_message_media_web_page:
    {
        auto media = std::make_shared<tgl_message_media_webpage>();
        media->webpage = tglf_fetch_alloc_webpage(DS_MM->webpage);
        return media;
    }
    case CODE_message_media_venue:
    {
        auto media = std::make_shared<tgl_message_media_venue>();
        tglf_fetch_geo(&media->geo, DS_MM->geo);
        media->title = DS_STDSTR(DS_MM->title);
        media->address = DS_STDSTR(DS_MM->address);
        media->provider = DS_STDSTR(DS_MM->provider);
        media->venue_id = DS_STDSTR(DS_MM->venue_id);
        return media;
    }
    case CODE_message_media_unsupported:
        return std::make_shared<tgl_message_media_unsupported>();
    default:
        assert(false);
        return nullptr;
    }
}

std::shared_ptr<tgl_message_media> tglf_fetch_message_media_encrypted(const tl_ds_decrypted_message_media* DS_DMM)
{
    if (!DS_DMM) {
        return nullptr;
    }

    switch (DS_DMM->magic) {
    case CODE_decrypted_message_media_empty:
        return std::make_shared<tgl_message_media_none>();
    case CODE_decrypted_message_media_photo:
    case CODE_decrypted_message_media_video:
    case CODE_decrypted_message_media_video_l12:
    case CODE_decrypted_message_media_document:
    case CODE_decrypted_message_media_audio:
    {
        //M->type = CODE_decrypted_message_media_video;
        auto media = std::make_shared<tgl_message_media_document_encr>();
        media->encr_document = std::make_shared<tgl_encr_document>();

        if (DS_DMM->mime_type && DS_DMM->mime_type->data) {
            media->encr_document->mime_type.resize(DS_DMM->mime_type->len);
            std::transform(DS_DMM->mime_type->data, DS_DMM->mime_type->data + DS_DMM->mime_type->len,
                    media->encr_document->mime_type.begin(), ::tolower);
        }

        switch (DS_DMM->magic) {
        case CODE_decrypted_message_media_photo:
            media->encr_document->type = tgl_document_type::image;
            if (media->encr_document->mime_type.empty()) {
                media->encr_document->mime_type = "image/jpeg"; // Default mime in case there is no mime from the message media
            }
            break;
        case CODE_decrypted_message_media_video:
        case CODE_decrypted_message_media_video_l12:
            media->encr_document->type = tgl_document_type::video;
            break;
        case CODE_decrypted_message_media_document:
            if (media->encr_document->mime_type.size() >= 6) {
                if (!media->encr_document->mime_type.compare(0, 6, "image/")) {
                    media->encr_document->type = tgl_document_type::image;
                    if (!media->encr_document->mime_type.compare(0, 9, "image/gif")) {
                        media->encr_document->is_animated = true;
                    }
                } else if (!media->encr_document->mime_type.compare(0, 6, "video/")) {
                    media->encr_document->type = tgl_document_type::video;
                } else if (!media->encr_document->mime_type.compare(0, 6, "audio/")) {
                    media->encr_document->type = tgl_document_type::audio;
                }
            }
            break;
        case CODE_decrypted_message_media_audio:
            media->encr_document->type = tgl_document_type::audio;
            break;
        }

        media->encr_document->w = DS_LVAL(DS_DMM->w);
        media->encr_document->h = DS_LVAL(DS_DMM->h);
        media->encr_document->size = DS_LVAL(DS_DMM->size);
        media->encr_document->duration = DS_LVAL(DS_DMM->duration);

        if (DS_DMM->thumb && DS_DMM->magic != CODE_photo_size_empty) {
            media->encr_document->thumb = tglf_fetch_photo_size(DS_DMM->thumb);
        }

        if (DS_DMM->str_thumb && DS_DMM->str_thumb->data) {
            media->encr_document->thumb_width = DS_LVAL(DS_DMM->thumb_w);
            media->encr_document->thumb_height = DS_LVAL(DS_DMM->thumb_h);
            media->encr_document->thumb_data.resize(DS_DMM->str_thumb->len);
            memcpy(media->encr_document->thumb_data.data(), DS_DMM->str_thumb->data, DS_DMM->str_thumb->len);
        }

        media->encr_document->key.resize(32);
        str_to_32(media->encr_document->key.data(), DS_STR(DS_DMM->key));
        media->encr_document->iv.resize(32);
        str_to_32(media->encr_document->iv.data(), DS_STR(DS_DMM->iv));

        return media;
    }
    case CODE_decrypted_message_media_geo_point:
    {
        auto media = std::make_shared<tgl_message_media_geo>();
        media->geo.latitude = DS_LVAL(DS_DMM->latitude);
        media->geo.longitude = DS_LVAL(DS_DMM->longitude);
        return media;
    }
    case CODE_decrypted_message_media_contact:
    {
        auto media = std::make_shared<tgl_message_media_contact>();
        media->phone = DS_STDSTR(DS_DMM->phone_number);
        media->first_name = DS_STDSTR(DS_DMM->first_name);
        media->last_name = DS_STDSTR(DS_DMM->last_name);
        media->user_id = DS_LVAL(DS_DMM->user_id);
        return media;
    }
    default:
        assert(false);
        return nullptr;
    }
}

std::shared_ptr<tgl_message_action> tglf_fetch_message_action_encrypted(const tl_ds_decrypted_message_action* DS_DMA)
{
    if (!DS_DMA) {
        return nullptr;
    }

    switch (DS_DMA->magic) {
    case CODE_decrypted_message_action_set_message_ttl:
        return std::make_shared<tgl_message_action_set_message_ttl>(DS_LVAL(DS_DMA->ttl_seconds));
    case CODE_decrypted_message_action_read_messages:
        return std::make_shared<tgl_message_action_read_messages>(DS_LVAL(DS_DMA->random_ids->cnt));
#if 0 // FIXME
        for (int i = 0; i < M->read_cnt; i++) {
          tgl_message_id_t id;
          id.peer_type = TGL_PEER_RANDOM_ID;
          id.id = DS_LVAL(DS_DMA->random_ids->data[i]);
          struct tgl_message* N = tgl_message_get(&id);
          if (N) {
            N->flags &= ~TGLMF_UNREAD;
          }
        }
#endif
    case CODE_decrypted_message_action_delete_messages:
    {
        std::vector<int64_t> messages_deleted;
        if (DS_DMA->random_ids) {
            for (int32_t i=0; i<*(DS_DMA->random_ids->cnt); ++i) {
                messages_deleted.push_back((*(DS_DMA->random_ids->data))[i]);
            }
        }
        return std::make_shared<tgl_message_action_delete_messages>(messages_deleted);
    }
    case CODE_decrypted_message_action_screenshot_messages:
        return std::make_shared<tgl_message_action_screenshot_messages>(DS_LVAL(DS_DMA->random_ids->cnt));
    case CODE_decrypted_message_action_notify_layer:
        return std::make_shared<tgl_message_action_notify_layer>(DS_LVAL(DS_DMA->layer));
    case CODE_decrypted_message_action_flush_history:
        return std::make_shared<tgl_message_action_flush_history>();
    case CODE_decrypted_message_action_typing:
        return std::make_shared<tgl_message_action_typing>(tglf_fetch_typing(DS_DMA->action));
    case CODE_decrypted_message_action_resend:
        return std::make_shared<tgl_message_action_resend>(DS_LVAL(DS_DMA->start_seq_no), DS_LVAL(DS_DMA->end_seq_no));
    case CODE_decrypted_message_action_noop:
        return std::make_shared<tgl_message_action_noop>();
    case CODE_decrypted_message_action_request_key:
    {
        auto action = std::make_shared<tgl_message_action_request_key>();
        action->exchange_id = DS_LVAL(DS_DMA->exchange_id);
        action->g_a.resize(256);
        str_to_256(action->g_a.data(), DS_STR(DS_DMA->g_a));
        return action;
    }
    case CODE_decrypted_message_action_accept_key:
    {
        auto action = std::make_shared<tgl_message_action_accept_key>();
        action->exchange_id = DS_LVAL(DS_DMA->exchange_id);
        action->g_a.resize(256);
        str_to_256(action->g_a.data(), DS_STR(DS_DMA->g_b));
        action->key_fingerprint = DS_LVAL(DS_DMA->key_fingerprint);
        return action;
    }
    case CODE_decrypted_message_action_commit_key:
        return std::make_shared<tgl_message_action_commit_key>(DS_LVAL(DS_DMA->exchange_id), DS_LVAL(DS_DMA->key_fingerprint));
    case CODE_decrypted_message_action_abort_key:
        return std::make_shared<tgl_message_action_abort_key>(DS_LVAL(DS_DMA->exchange_id));
    default:
        assert(false);
        return nullptr;
    }
}

static std::shared_ptr<tgl_message_entity> tglf_fetch_message_entity(const tl_ds_message_entity* DS_ME)
{
    auto entity = std::make_shared<tgl_message_entity>();
    entity->start = DS_LVAL(DS_ME->offset);
    entity->length = DS_LVAL(DS_ME->length);
    switch (DS_ME->magic) {
    case CODE_message_entity_unknown:
        entity->type = tgl_message_entity_type::unknown;
        break;
    case CODE_message_entity_mention:
        entity->type = tgl_message_entity_type::mention;
        break;
    case CODE_message_entity_hashtag:
        entity->type = tgl_message_entity_type::hashtag;
        break;
    case CODE_message_entity_bot_command:
        entity->type = tgl_message_entity_type::bot_command;
        break;
    case CODE_message_entity_url:
        entity->type = tgl_message_entity_type::url;
        break;
    case CODE_message_entity_email:
        entity->type = tgl_message_entity_type::email;
        break;
    case CODE_message_entity_bold:
        entity->type = tgl_message_entity_type::bold;
        break;
    case CODE_message_entity_italic:
        entity->type = tgl_message_entity_type::italic;
        break;
    case CODE_message_entity_code:
        entity->type = tgl_message_entity_type::code;
        break;
    case CODE_message_entity_pre:
        entity->type = tgl_message_entity_type::pre;
        break;
    case CODE_message_entity_text_url:
        entity->type = tgl_message_entity_type::text_url;
        entity->text_url = DS_STDSTR(DS_ME->url);
        break;
    default:
        assert(false);
        break;
    }

    return entity;
}

void tglf_fetch_message_entities(const std::shared_ptr<tgl_message>& M, const tl_ds_vector* DS)
{
    int entities_num = DS_LVAL(DS->f1);
    M->entities.resize(entities_num);
    for (int i = 0; i < entities_num; i++) {
        const tl_ds_message_entity* D = static_cast<const tl_ds_message_entity*>(DS->f2[i]);
        M->entities[i] = tglf_fetch_message_entity(D);
    }
}

std::shared_ptr<tgl_message> tglf_fetch_alloc_message(const tl_ds_message* DS_M)
{
    if (!DS_M || DS_M->magic == CODE_message_empty) {
        TGL_NOTICE("empty message");
        return nullptr;
    }

    tgl_peer_id_t temp_to_id = tglf_fetch_peer_id(DS_M->to_id);
    tgl_input_peer_t to_id(temp_to_id.peer_type, temp_to_id.peer_id, 0);

    int32_t flags = DS_LVAL(DS_M->flags);

    tgl_peer_id_t from_id;
    if (DS_M->from_id) {
        from_id = tgl_peer_id_t(tgl_peer_type::user, DS_LVAL(DS_M->from_id));
    } else if (DS_M->to_id->magic == CODE_peer_channel) {
        if (flags & 2) {
            from_id = tgl_state::instance()->our_id();
        } else {
            from_id = tgl_peer_id_t::from_input_peer(to_id);
        }
    } else {
        from_id = tgl_peer_id_t(tgl_peer_type::user, 0);
    }

    int64_t message_id = DS_LVAL(DS_M->id);

    tgl_peer_id_t fwd_from_id;
    if (DS_M->fwd_from_id) {
        fwd_from_id = tglf_fetch_peer_id(DS_M->fwd_from_id);
    } else {
        fwd_from_id = tgl_peer_id_t(tgl_peer_type::user, 0);
    }

    int64_t fwd_date = DS_LVAL(DS_M->fwd_date);
    int64_t date = DS_LVAL(DS_M->date);
    std::shared_ptr<tgl_message> M = std::make_shared<tgl_message>(message_id,
        from_id,
        to_id,
        DS_M->fwd_from_id ? &fwd_from_id : nullptr,
        &fwd_date,
        &date,
        DS_STDSTR(DS_M->message),
        DS_M->media,
        DS_M->action,
        DS_LVAL(DS_M->reply_to_msg_id),
        DS_M->reply_markup);
    M->set_unread(flags&1).set_outgoing(flags&2).set_mention(flags&16);
    return M;
}

static int decrypt_encrypted_message(const std::shared_ptr<tgl_secret_chat>& secret_chat, int*& decr_ptr, int* decr_end)
{
    int* msg_key = decr_ptr;
    decr_ptr += 4;
    assert(decr_ptr < decr_end);
    unsigned char sha1a_buffer[20];
    unsigned char sha1b_buffer[20];
    unsigned char sha1c_buffer[20];
    unsigned char sha1d_buffer[20];

    unsigned char buf[64];

    memset(sha1a_buffer, 0, sizeof(sha1a_buffer));
    memset(sha1b_buffer, 0, sizeof(sha1b_buffer));
    memset(sha1c_buffer, 0, sizeof(sha1c_buffer));
    memset(sha1d_buffer, 0, sizeof(sha1d_buffer));
    memset(buf, 0, sizeof(buf));

    const int* e_key = secret_chat->exchange_state() != tgl_secret_chat_exchange_state::committed
        ? reinterpret_cast<const int32_t*>(secret_chat->key()) : reinterpret_cast<const int32_t*>(secret_chat->exchange_key());

    memcpy(buf, msg_key, 16);
    memcpy(buf + 16, e_key, 32);
    TGLC_sha1(buf, 48, sha1a_buffer);

    memcpy(buf, e_key + 8, 16);
    memcpy(buf + 16, msg_key, 16);
    memcpy(buf + 32, e_key + 12, 16);
    TGLC_sha1(buf, 48, sha1b_buffer);

    memcpy(buf, e_key + 16, 32);
    memcpy(buf + 32, msg_key, 16);
    TGLC_sha1(buf, 48, sha1c_buffer);

    memcpy(buf, msg_key, 16);
    memcpy(buf + 16, e_key + 24, 32);
    TGLC_sha1(buf, 48, sha1d_buffer);

    unsigned char key[32];
    memset(key, 0, sizeof(key));
    memcpy(key, sha1a_buffer + 0, 8);
    memcpy(key + 8, sha1b_buffer + 8, 12);
    memcpy(key + 20, sha1c_buffer + 4, 12);

    unsigned char iv[32];
    memset(iv, 0, sizeof(iv));
    memcpy(iv, sha1a_buffer + 8, 12);
    memcpy(iv + 12, sha1b_buffer + 0, 8);
    memcpy(iv + 20, sha1c_buffer + 16, 4);
    memcpy(iv + 24, sha1d_buffer + 0, 8);

    TGLC_aes_key aes_key;
    TGLC_aes_set_decrypt_key(key, 256, &aes_key);
    TGLC_aes_ige_encrypt(reinterpret_cast<const unsigned char*>(decr_ptr),
            reinterpret_cast<unsigned char*>(decr_ptr), 4 * (decr_end - decr_ptr), &aes_key, iv, 0);
    memset(&aes_key, 0, sizeof(aes_key));

    int x = *decr_ptr;
    if (x < 0 || (x & 3)) {
        return -1;
    }
    assert(x >= 0 && !(x & 3));
    TGLC_sha1(reinterpret_cast<const unsigned char*>(decr_ptr), 4 + x, sha1a_buffer);

    if (memcmp(sha1a_buffer + 4, msg_key, 16)) {
        return -1;
    }

    return 0;
}

std::shared_ptr<tgl_message> tglf_fetch_encrypted_message(const tl_ds_encrypted_message* DS_EM)
{
    if (!DS_EM) {
        return nullptr;
    }

    std::shared_ptr<tgl_secret_chat> secret_chat = tgl_state::instance()->secret_chat_for_id(DS_LVAL(DS_EM->chat_id));
    if (!secret_chat || secret_chat->state() != tgl_secret_chat_state::ok) {
        TGL_WARNING("encrypted message to unknown chat, dropping");
        return nullptr;
    }

    int64_t message_id = DS_LVAL(DS_EM->random_id);

    int32_t* decr_ptr = reinterpret_cast<int32_t*>(DS_EM->bytes->data);
    int32_t* decr_end = decr_ptr + (DS_EM->bytes->len / 4);

    if (secret_chat->exchange_state() == tgl_secret_chat_exchange_state::committed && secret_chat->key_fingerprint() == *(int64_t*)decr_ptr) {
        tgl_do_confirm_exchange(secret_chat, 0);
        assert(secret_chat->exchange_state() == tgl_secret_chat_exchange_state::none);
    }

    int64_t key_fingerprint = secret_chat->exchange_state() != tgl_secret_chat_exchange_state::committed ? secret_chat->key_fingerprint() : secret_chat->exchange_key_fingerprint();
    if (*(int64_t*)decr_ptr != key_fingerprint) {
        TGL_WARNING("encrypted message with bad fingerprint to chat " << secret_chat->id().peer_id);
        return nullptr;
    }

    decr_ptr += 2;

    if (decrypt_encrypted_message(secret_chat, decr_ptr, decr_end) < 0) {
        TGL_WARNING("can not decrypt message");
        return nullptr;
    }

    int32_t decrypted_data_length = *decr_ptr; // decrypted data length
    tgl_in_buffer in = { decr_ptr, decr_ptr + decrypted_data_length / 4 + 1 };
    auto result = fetch_i32(&in);
    TGL_ASSERT_UNUSED(result, result == decrypted_data_length);

    std::shared_ptr<tgl_message> message;
    if (*in.ptr == CODE_decrypted_message_layer) {
        struct paramed_type decrypted_message_layer = TYPE_TO_PARAM(decrypted_message_layer);
        tgl_in_buffer skip_in = in;
        if (skip_type_decrypted_message_layer(&skip_in, &decrypted_message_layer) < 0 || skip_in.ptr != skip_in.end) {
            TGL_WARNING("can not fetch message");
            return nullptr;
        }

        struct tl_ds_decrypted_message_layer* DS_DML = fetch_ds_type_decrypted_message_layer(&in, &decrypted_message_layer);
        assert(DS_DML);

        struct tl_ds_decrypted_message* DS_DM = DS_DML->message;
        if (message_id != DS_LVAL(DS_DM->random_id)) {
            TGL_ERROR("incorrect message: id = " << message_id << ", new_id = " << DS_LVAL(DS_DM->random_id));
            free_ds_type_decrypted_message_layer(DS_DML, &decrypted_message_layer);
            return nullptr;
        }

        tgl_peer_id_t from_id = tgl_peer_id_t(tgl_peer_type::user, secret_chat->user_id());

        int64_t date = DS_LVAL(DS_EM->date);
        message = std::make_shared<tgl_message>(secret_chat,
                message_id,
                from_id,
                &date,
                DS_STDSTR(DS_DM->message),
                DS_DM->media,
                DS_DM->action,
                DS_EM->file,
                DS_LVAL(DS_DML->layer), DS_LVAL(DS_DML->in_seq_no), DS_LVAL(DS_DML->out_seq_no));

        free_ds_type_decrypted_message_layer(DS_DML, &decrypted_message_layer);
    } else {
        // Pre-layer 17 encrypted message
        struct paramed_type decrypted_message = TYPE_TO_PARAM(decrypted_message);
        tgl_in_buffer skip_in = in;
        if (skip_type_decrypted_message(&skip_in, &decrypted_message) < 0 || skip_in.ptr != skip_in.end) {
            TGL_WARNING("can not fetch message");
            return NULL;
        }

        struct tl_ds_decrypted_message* DS_DM = fetch_ds_type_decrypted_message(&in, &decrypted_message);
        assert(DS_DM);

        int layer = 8; // default secret chat layer is 8
        if (DS_DM->action && DS_DM->action->magic == CODE_decrypted_message_action_notify_layer) {
            layer = *(DS_DM->action->layer);
        }

        tgl_peer_id_t from_id = tgl_peer_id_t(tgl_peer_type::user, secret_chat->user_id());

        int64_t date = DS_LVAL(DS_EM->date);
        message = std::make_shared<tgl_message>(secret_chat,
                message_id,
                from_id,
                &date,
                DS_STDSTR(DS_DM->message),
                DS_DM->media,
                DS_DM->action,
                DS_EM->file,
                layer, -1, -1);
    }

    return message;
}

void tglf_fetch_encrypted_message_file(const std::shared_ptr<tgl_message_media>& M, const tl_ds_encrypted_file* DS_EF)
{
    if (DS_EF->magic == CODE_encrypted_file_empty) {
        assert(M->type() != tgl_message_media_type::document_encr);
    } else {
        assert(M->type() == tgl_message_media_type::document_encr);
        if (M->type() != tgl_message_media_type::document_encr) {
            return;
        }

        auto media = std::static_pointer_cast<tgl_message_media_document_encr>(M);

        assert(media->encr_document);
        if (!media->encr_document) {
            return;
        }

        media->encr_document->id = DS_LVAL(DS_EF->id);
        media->encr_document->access_hash = DS_LVAL(DS_EF->access_hash);
        media->encr_document->size = DS_LVAL(DS_EF->size);
        media->encr_document->dc_id = DS_LVAL(DS_EF->dc_id);
        media->encr_document->key_fingerprint = DS_LVAL(DS_EF->key_fingerprint);
    }
}

static void process_encrypted_messages(const std::shared_ptr<tgl_secret_chat>& secret_chat,
        const std::vector<std::shared_ptr<tgl_message>>& messages);

void tglf_encrypted_message_received(const std::shared_ptr<tgl_message>& message)
{
    std::shared_ptr<tgl_secret_chat> secret_chat = tgl_state::instance()->secret_chat_for_id(message->to_id);
    assert(secret_chat);

    message->set_unread(true);

    int32_t raw_in_seq_no = message->secret_message_meta->raw_in_seq_no;
    int32_t raw_out_seq_no = message->secret_message_meta->raw_out_seq_no;
    int32_t layer = message->secret_message_meta->layer;

    TGL_DEBUG("secret message received: in_seq_no = " << raw_in_seq_no / 2 << " out_seq_no = " << raw_out_seq_no / 2 << " layer = " << layer);

    if (raw_in_seq_no >= 0 && raw_out_seq_no >= 0) {
        if ((raw_out_seq_no & 1) != 1 - (secret_chat->admin_id() == tgl_state::instance()->our_id().peer_id) ||
            (raw_in_seq_no & 1) != (secret_chat->admin_id() == tgl_state::instance()->our_id().peer_id)) {
            TGL_WARNING("bad secret message admin, dropping");
            return;
        }

        if (raw_in_seq_no / 2 > secret_chat->out_seq_no()) {
            TGL_WARNING("in_seq_no " << raw_in_seq_no / 2 << " of remote client is bigger than our out_seq_no of "
                    << secret_chat->out_seq_no() << ", dropping the message");
            return;
        }

        if (raw_out_seq_no / 2 < secret_chat->in_seq_no()) {
            TGL_WARNING("secret message recived with out_seq_no less than the in_seq_no: out_seq_no = "
                    << raw_out_seq_no / 2 << " in_seq_no = " << secret_chat->in_seq_no());
            return;
        } else if (raw_out_seq_no / 2 > secret_chat->in_seq_no()) {
            TGL_WARNING("hole in seq in secret chat, expecting in_seq_no of "
                    << secret_chat->in_seq_no() << " but " << raw_out_seq_no / 2 << " was received");

            // FIXME: We may need to discard the secret chat if there are a lot of holes.

            std::weak_ptr<tgl_secret_chat> weak_secret_chat(secret_chat);
            secret_chat->private_facet()->queue_pending_received_message(message, 3.0, [=] {
                auto chat = weak_secret_chat.lock();
                if (chat && chat->private_facet()->has_hole()) {
                    process_encrypted_messages(chat, chat->private_facet()->heal_all_holes());
                }
            });
            return;
        }

        process_encrypted_messages(secret_chat, secret_chat->private_facet()->dequeue_pending_received_messages(message));
    } else if (raw_in_seq_no < 0 && raw_out_seq_no < 0) { // Pre-layer 17 message
        process_encrypted_messages(secret_chat, { message });
    } else {
        TGL_WARNING("the secret message sequence number is weird: raw_in_seq_no = " << raw_in_seq_no << " raw_out_seq_no = " << raw_out_seq_no);
    }
}

static void process_encrypted_messages(const std::shared_ptr<tgl_secret_chat>& secret_chat,
        const std::vector<std::shared_ptr<tgl_message>>& messages)
{
    if (messages.empty()) {
        return;
    }

    std::vector<std::shared_ptr<tgl_message>> none_action_messages;
    for (const auto& message: messages) {
        if (message->secret_message_meta->raw_out_seq_no >= 0 && message->from_id.peer_id != tgl_state::instance()->our_id().peer_id) {
            message->seq_no = message->secret_message_meta->raw_out_seq_no / 2;
        }
        auto action_type = message->action ? message->action->type() : tgl_message_action_type::none;
        if (action_type == tgl_message_action_type::none) {
            none_action_messages.push_back(message);
        } else if (action_type == tgl_message_action_type::request_key) {
            auto action = std::static_pointer_cast<tgl_message_action_request_key>(message->action);
            if (secret_chat->exchange_state() == tgl_secret_chat_exchange_state::none || (secret_chat->exchange_state() == tgl_secret_chat_exchange_state::requested && secret_chat->exchange_id() > action->exchange_id )) {
                tgl_do_accept_exchange(secret_chat, action->exchange_id, action->g_a);
            } else {
                TGL_WARNING("secret_chat exchange: incorrect state (received request, state = " << secret_chat->exchange_state() << ")");
            }
        } else if (action_type == tgl_message_action_type::accept_key) {
            auto action = std::static_pointer_cast<tgl_message_action_accept_key>(message->action);
            if (secret_chat->exchange_state() == tgl_secret_chat_exchange_state::requested && secret_chat->exchange_id() == action->exchange_id) {
                tgl_do_commit_exchange(secret_chat, action->g_a);
            } else {
                TGL_WARNING("secret_chat exchange: incorrect state (received accept, state = " << secret_chat->exchange_state() << ")");
            }
        } else if (action_type == tgl_message_action_type::commit_key) {
            auto action = std::static_pointer_cast<tgl_message_action_commit_key>(message->action);
            if (secret_chat->exchange_state() == tgl_secret_chat_exchange_state::accepted && secret_chat->exchange_id() == action->exchange_id) {
                tgl_do_confirm_exchange(secret_chat, 1);
            } else {
                TGL_WARNING("secret_chat exchange: incorrect state (received commit, state = " << secret_chat->exchange_state() << ")");
            }
        } else if (action_type == tgl_message_action_type::abort_key) {
            auto action = std::static_pointer_cast<tgl_message_action_abort_key>(message->action);
            if (secret_chat->exchange_state() != tgl_secret_chat_exchange_state::none && secret_chat->exchange_id() == action->exchange_id) {
                tgl_do_abort_exchange(secret_chat);
            } else {
                TGL_WARNING("secret_chat exchange: incorrect state (received abort, state = " << secret_chat->exchange_state() << ")");
            }
        } else if (action_type == tgl_message_action_type::notify_layer) {
            auto action = std::static_pointer_cast<tgl_message_action_notify_layer>(message->action);
            secret_chat->private_facet()->set_layer(action->layer);
        } else if (action_type == tgl_message_action_type::set_message_ttl) {
            auto action = std::static_pointer_cast<tgl_message_action_set_message_ttl>(message->action);
            secret_chat->private_facet()->set_ttl(action->ttl);
        } else if (action_type == tgl_message_action_type::delete_messages) {
            auto action = std::static_pointer_cast<tgl_message_action_delete_messages>(message->action);
            for (int64_t id : action->msg_ids) {
                tgl_state::instance()->callback()->message_deleted(id);
            }
        } else if (action_type == tgl_message_action_type::resend) {
            //FIXME implement this
            auto action = std::static_pointer_cast<tgl_message_action_resend>(message->action);
            TGL_WARNING("received request for message resend; start-seq: "<< action->start_seq_no << " end-seq: " << action->end_seq_no);
        }
    }

    secret_chat->private_facet()->set_in_seq_no(messages.back()->secret_message_meta->raw_out_seq_no / 2 + 1);
    tgl_state::instance()->callback()->secret_chat_update(secret_chat);

    if (none_action_messages.size()) {
        tgl_state::instance()->callback()->new_messages(none_action_messages);
    }
}

std::shared_ptr<tgl_bot_info> tglf_fetch_alloc_bot_info(const tl_ds_bot_info* DS_BI)
{
    if (!DS_BI || DS_BI->magic == CODE_bot_info_empty) {
        return nullptr;
    }

    std::shared_ptr<tgl_bot_info> bot = std::make_shared<tgl_bot_info>();
    bot->version = DS_LVAL(DS_BI->version);
    bot->share_text = DS_STDSTR(DS_BI->share_text);
    bot->description = DS_STDSTR(DS_BI->description);

    int commands_num = DS_LVAL(DS_BI->commands->cnt);
    bot->commands.resize(commands_num);
    for (int i = 0; i < commands_num; i++) {
        const tl_ds_bot_command* bot_command = DS_BI->commands->data[i];
        bot->commands[i] = std::make_shared<tgl_bot_command>();
        bot->commands[i]->command = DS_STDSTR(bot_command->command);
        bot->commands[i]->description = DS_STDSTR(bot_command->description);
    }
    return bot;
}

std::shared_ptr<tgl_message_reply_markup> tglf_fetch_alloc_reply_markup(const tl_ds_reply_markup* DS_RM)
{
    if (!DS_RM) {
        return nullptr;
    }

    auto reply_markup = std::make_shared<tgl_message_reply_markup>();
    reply_markup->flags = DS_LVAL(DS_RM->flags);
    int rows = DS_RM->rows ? DS_LVAL(DS_RM->rows->cnt) : 0;
    if (rows <= 0) {
        return reply_markup;
    }

    reply_markup->button_matrix.resize(rows);
    for (int i = 0; i < rows; ++i) {
        const tl_ds_keyboard_button_row* row = DS_RM->rows->data[i];
        int button_count = DS_LVAL(row->buttons->cnt);
        reply_markup->button_matrix[i].resize(button_count);
        for (int j = 0; j < button_count; ++j) {
            const tl_ds_keyboard_button* button = row->buttons->data[j];
            if (button && button->text && button->text->data) {
                reply_markup->button_matrix[i][j] = std::string(button->text->data, button->text->len);
            }
        }
    }

    return reply_markup;
}
/* }}} */
