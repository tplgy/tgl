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
#include "chat.h"
#include "channel.h"
#include "crypto/tgl_crypto_aes.h"
#include "crypto/tgl_crypto_bn.h"
#include "crypto/tgl_crypto_sha.h"
#include "document.h"
#include "mtproto_client.h"
#include "mtproto-common.h"
#include "tgl/tgl_bot.h"
#include "tgl/tgl_secret_chat.h"
#include "tgl/tgl_update_callback.h"
#include "tgl/tgl_user.h"
#include "tgl_secret_chat_private.h"
#include "updater.h"
#include "user.h"
#include "user_agent.h"

#include <algorithm>
#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>

namespace tgl {
namespace impl {

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

inline static void str_to_256(unsigned char* dst, const char* src, int src_len)
{
    if (src_len >= 256) {
        memcpy(dst, src + src_len - 256, 256);
    } else {
        memset(dst, 0, 256 - src_len);
        memcpy(dst + 256 - src_len, src, src_len);
    }
}

std::shared_ptr<tgl_secret_chat> tglf_fetch_alloc_encrypted_chat(user_agent* ua, const tl_ds_encrypted_chat* DS_EC)
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

    std::shared_ptr<tgl_secret_chat> secret_chat = ua->secret_chat_for_id(chat_id);

    bool is_new = false;
    if (!secret_chat) {
        int admin_id = DS_LVAL(DS_EC->id);

        if (!admin_id) {
            // It must be a secret chat which is encryptedChatDiscarded#13d6dd27.
            // For a discarded secret chat which is not on our side either, we do nothing.
            TGL_DEBUG("discarded secret chat " << chat_id.peer_id << " found, doing nothing");
            return nullptr;
        }

        if (admin_id != ua->our_id().peer_id) {
            // It must be a new secret chat requested from the peer.
            secret_chat = ua->allocate_secret_chat(chat_id, DS_LVAL(DS_EC->participant_id));
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
        secret_chat->private_facet()->set_deleted();
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

        int32_t user_id = DS_LVAL(DS_EC->participant_id) + DS_LVAL(DS_EC->admin_id) - ua->our_id().peer_id;
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
        tgl_secret_chat_state state;
        if (DS_EC->magic == CODE_encrypted_chat_waiting) {
            state = tgl_secret_chat_state::waiting;
        } else {
            state = tgl_secret_chat_state::ok;
            str_to_256(g_key, DS_STR(DS_EC->g_a_or_b));
            secret_chat->private_facet()->set_temp_key_fingerprint(DS_LVAL(DS_EC->key_fingerprint));
            secret_chat->private_facet()->set_g_key(g_key, sizeof(g_key));
        }
        if (DS_EC->access_hash) {
            secret_chat->private_facet()->set_access_hash(*(DS_EC->access_hash));
        }
        if (DS_EC->date) {
            secret_chat->private_facet()->set_date(*(DS_EC->date));
        }
        secret_chat->private_facet()->set_state(state);
    }

    return secret_chat;
}

std::shared_ptr<tgl_photo_size> tglf_fetch_photo_size(const tl_ds_photo_size* DS_PS)
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

std::shared_ptr<tgl_webpage> tglf_fetch_alloc_webpage(const tl_ds_web_page* DS_W)
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
        return action;
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

std::shared_ptr<tgl_message> tglf_fetch_alloc_message_short(user_agent* ua, const tl_ds_updates* DS_U)
{
    tgl_peer_id_t peer_id = tgl_peer_id_t(tgl_peer_type::user, DS_LVAL(DS_U->user_id));

    int64_t message_id = DS_LVAL(DS_U->id);
    int32_t flags = DS_LVAL(DS_U->flags);

//    struct tl_ds_message_media A;
//    A.magic = CODE_message_media_empty;

    tgl_peer_id_t our_id = ua->our_id();

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
    msg->seq_no = message_id;
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
    message->seq_no = message_id;
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
        media->document = std::make_shared<document>(DS_MM->video);
        media->caption = DS_STDSTR(DS_MM->caption);
        return media;
    }
    case CODE_message_media_audio:
    {
        auto media = std::make_shared<tgl_message_media_audio>();
        media->document = std::make_shared<document>(DS_MM->audio);
        media->caption = DS_STDSTR(DS_MM->caption);
        return media;
    }
    case CODE_message_media_document:
    {
        auto media = std::make_shared<tgl_message_media_document>();
        media->document = std::make_shared<document>(DS_MM->document);
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
        auto media = std::make_shared<tgl_message_media_document>();
        media->document = std::make_shared<document>(DS_DMM);
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
    case CODE_decrypted_message_action_opaque_message:
    {
        auto action = std::make_shared<tgl_message_action_opaque_message>();
        action->message = DS_STDSTR(DS_DMA->message);
        return action;
    }
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

std::shared_ptr<tgl_message> tglf_fetch_alloc_message(user_agent* ua, const tl_ds_message* DS_M)
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
            from_id = ua->our_id();
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
    M->seq_no = message_id;
    return M;
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

}
}
