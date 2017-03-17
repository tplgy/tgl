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

#include "message.h"

#include "auto/auto-fetch-ds.h"
#include "auto/auto-types.h"
#include "auto/constants.h"
#include "document.h"
#include "secret_chat.h"
#include "structures.h"
#include "tgl/tgl_log.h"

#include <cassert>
#include <cctype>
#include <cstring>

namespace tgl {
namespace impl {

inline static void str_to_256(unsigned char* dst, const char* src, int src_len)
{
    if (src_len >= 256) {
        memcpy(dst, src + src_len - 256, 256);
    } else {
        memset(dst, 0, 256 - src_len);
        memcpy(dst + 256 - src_len, src, src_len);
    }
}

static std::shared_ptr<tgl_message_entity> make_message_entity(const tl_ds_message_entity* DS_ME)
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

static std::shared_ptr<tgl_message_media> make_message_media(const tl_ds_message_media* DS_MM)
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
        media->geo.longitude = DS_LVAL(DS_MM->geo->longitude);
        media->geo.latitude = DS_LVAL(DS_MM->geo->latitude);
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
        media->geo.longitude = DS_LVAL(DS_MM->geo->longitude);
        media->geo.latitude = DS_LVAL(DS_MM->geo->latitude);
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

static std::shared_ptr<tgl_message_media> make_message_media_encrypted(const tl_ds_decrypted_message_media* DS_DMM)
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

static std::shared_ptr<tgl_message_action> make_message_action(const tl_ds_message_action* DS_MA)
{
    if (!DS_MA) {
        return nullptr;
    }

    switch (DS_MA->magic) {
    case CODE_message_action_empty:
        return std::make_shared<tgl_message_action_none>();
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

static std::shared_ptr<tgl_message_action> make_message_action_encrypted(const tl_ds_decrypted_message_action* DS_DMA)
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

static std::shared_ptr<tgl_message_reply_markup> make_message_reply_markup(const tl_ds_reply_markup* DS_RM)
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

std::shared_ptr<message> message::create(const tgl_peer_id_t& our_id, const tl_ds_message* DS_M)
{
    if (!DS_M || DS_M->magic == CODE_message_empty) {
        TGL_DEBUG("empty message");
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
            from_id = our_id;
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
    auto m = std::make_shared<message>(message_id,
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
    m->set_unread(flags&1).set_outgoing(flags&2).set_mention(flags&16);
    m->set_sequence_number(message_id);
    return m;
}

std::shared_ptr<message> message::create_from_short_update(const tgl_peer_id_t& our_id, const tl_ds_updates* DS_U)
{
    tgl_peer_id_t peer_id = tgl_peer_id_t(tgl_peer_type::user, DS_LVAL(DS_U->user_id));

    int64_t message_id = DS_LVAL(DS_U->id);
    int32_t flags = DS_LVAL(DS_U->flags);

    tgl_peer_id_t fwd_from_id;
    if (DS_U->fwd_from_id) {
        fwd_from_id = tglf_fetch_peer_id(DS_U->fwd_from_id);
    } else {
        fwd_from_id = tgl_peer_id_t(tgl_peer_type::user, 0);
    }

    int64_t fwd_date = DS_LVAL(DS_U->fwd_date);
    int64_t date = DS_LVAL(DS_U->date);
    std::shared_ptr<message> m = std::make_shared<message>(message_id,
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
    m->set_unread(flags&1).set_outgoing(flags&2).set_mention(flags&16);
    m->set_sequence_number(message_id);
    return m;
}

std::shared_ptr<message> message::create_chat_message_from_short_update(const tl_ds_updates* DS_U)
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
    auto m = std::make_shared<message>(message_id,
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
    m->set_unread(flags&1).set_outgoing(flags&2).set_mention(flags&16);
    m->set_sequence_number(message_id);
    return m;
}

message::message()
    : m_id(0)
    , m_forward_date(0)
    , m_date(0)
    , m_reply_id(0)
    , m_sequence_number(0)
    , m_forward_from_id()
    , m_from_id()
    , m_to_id()
    , m_action(std::make_shared<tgl_message_action_none>())
    , m_media(std::make_shared<tgl_message_media_none>())
    , m_flags()
{
}

message::message(int64_t message_id,
        const tgl_peer_id_t& from_id,
        const tgl_input_peer_t& to_id,
        const tgl_peer_id_t* forward_from_id,
        const int64_t* forward_date,
        const int64_t* date,
        const std::string& text,
        const tl_ds_message_media* media,
        const tl_ds_message_action* action,
        int32_t reply_id,
        const tl_ds_reply_markup* reply_markup)
    : message()
{
    m_id = message_id;
    m_from_id = from_id;
    m_to_id = to_id;

    if (date) {
        m_date = *date;
    }

    if (forward_from_id) {
        m_forward_from_id = *forward_from_id;
    }

    if (forward_date) {
        m_forward_date = *forward_date;
    }

    if (action) {
        m_action = make_message_action(action);
        set_service(true);
    }

    m_text = text;

    if (media) {
        m_media = make_message_media(media);
        assert(!is_service());
    }

    m_reply_id = reply_id;

    if (reply_markup) {
        m_reply_markup = make_message_reply_markup(reply_markup);
    }
}

message::message(const std::shared_ptr<secret_chat>& sc,
        int64_t message_id,
        const tgl_peer_id_t& from_id,
        const int64_t* date,
        const std::string& text,
        const tl_ds_decrypted_message_media* media,
        const tl_ds_decrypted_message_action* action,
        const tl_ds_encrypted_file* file)
    : message(message_id, from_id, sc->id(), nullptr, nullptr, date, text, nullptr, nullptr, 0, nullptr)
{
    if (action) {
        if (action->magic == CODE_decrypted_message_action_opaque_message
                && !sc->opaque_service_message_enabled()) {
            // ignore the action.
        } else {
            m_action = make_message_action_encrypted(action);
            set_service(true);
        }
    }

    if (media) {
        m_media = make_message_media_encrypted(media);
        assert(!is_service());
    }

    if (file && file->magic == CODE_encrypted_file && m_media->type() == tgl_message_media_type::document) {
        auto doc = std::static_pointer_cast<tgl_message_media_document>(m_media)->document;
        std::static_pointer_cast<document>(doc)->update(file);
    }

    set_outgoing(from_id.peer_id == sc->our_id().peer_id);

    if (action && !is_outgoing() && m_action && m_action->type() == tgl_message_action_type::notify_layer) {
        // FIXME is following right?
        sc->set_layer(std::static_pointer_cast<tgl_message_action_notify_layer>(m_action)->layer);
    }
}

void message::set_decrypted_message_media(const tl_ds_decrypted_message_media* media)
{
    if (media) {
        m_media = make_message_media_encrypted(media);
        assert(!is_service());
    } else {
        m_media = nullptr;
    }
}


void message::update_entities(const tl_ds_vector* DS)
{
    int32_t entities_num = DS_LVAL(DS->f1);
    m_entities.resize(entities_num);
    for (int32_t i = 0; i < entities_num; ++i) {
        const tl_ds_message_entity* entity = static_cast<const tl_ds_message_entity*>(DS->f2[i]);
        m_entities[i] = make_message_entity(entity);
    }
}

}
}
