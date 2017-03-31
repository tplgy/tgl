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

#include "message_entity.h"

#include "auto/auto.h"
#include "auto/auto_types.h"
#include "mtproto_common.h"

#include <cassert>

namespace tgl {
namespace impl {

std::shared_ptr<tgl_message_entity> create_message_entity(const tl_ds_message_entity* DS_ME)
{
    auto entity = std::make_shared<tgl_message_entity>();
    entity->start = DS_LVAL(DS_ME->offset);
    entity->length = DS_LVAL(DS_ME->length);
    switch (DS_ME->magic) {
    case CODE_message_entity_unknown:
        entity->type = tgl_message_entity_type::unknown;
        return entity;
    case CODE_message_entity_mention:
        entity->type = tgl_message_entity_type::mention;
        return entity;
    case CODE_message_entity_hashtag:
        entity->type = tgl_message_entity_type::hashtag;
        return entity;
    case CODE_message_entity_bot_command:
        entity->type = tgl_message_entity_type::bot_command;
        return entity;
    case CODE_message_entity_url:
        entity->type = tgl_message_entity_type::url;
        return entity;
    case CODE_message_entity_email:
        entity->type = tgl_message_entity_type::email;
        return entity;
    case CODE_message_entity_bold:
        entity->type = tgl_message_entity_type::bold;
        return entity;
    case CODE_message_entity_italic:
        entity->type = tgl_message_entity_type::italic;
        return entity;
    case CODE_message_entity_code:
        entity->type = tgl_message_entity_type::code;
        return entity;
    case CODE_message_entity_pre:
        entity->type = tgl_message_entity_type::pre;
        entity->text_url_or_language = DS_STDSTR(DS_ME->language);
        return entity;
    case CODE_message_entity_text_url:
        entity->type = tgl_message_entity_type::text_url;
        entity->text_url_or_language = DS_STDSTR(DS_ME->url);
        return entity;
    }

    assert(false);
    return nullptr;
}

void serialize_message_entity(mtprotocol_serializer* s, const tgl_message_entity* entity)
{
    switch (entity->type) {
    case tgl_message_entity_type::bold:
        s->out_i32(CODE_message_entity_bold);
        s->out_i32(entity->start);
        s->out_i32(entity->length);
        return;
    case tgl_message_entity_type::italic:
        s->out_i32(CODE_message_entity_italic);
        s->out_i32(entity->start);
        s->out_i32(entity->length);
        return;
    case tgl_message_entity_type::code:
        s->out_i32(CODE_message_entity_code);
        s->out_i32(entity->start);
        s->out_i32(entity->length);
        return;
    case tgl_message_entity_type::text_url:
        s->out_i32(CODE_message_entity_text_url);
        s->out_i32(entity->start);
        s->out_i32(entity->length);
        s->out_std_string(entity->text_url_or_language);
        return;
    case tgl_message_entity_type::unknown:
        s->out_i32(CODE_message_entity_unknown);
        s->out_i32(entity->start);
        s->out_i32(entity->length);
        return;
    case tgl_message_entity_type::mention:
        s->out_i32(CODE_message_entity_mention);
        s->out_i32(entity->start);
        s->out_i32(entity->length);
        return;
    case tgl_message_entity_type::hashtag:
        s->out_i32(CODE_message_entity_hashtag);
        s->out_i32(entity->start);
        s->out_i32(entity->length);
        return;
    case tgl_message_entity_type::bot_command:
        s->out_i32(CODE_message_entity_bot_command);
        s->out_i32(entity->start);
        s->out_i32(entity->length);
        return;
    case tgl_message_entity_type::url:
        s->out_i32(CODE_message_entity_url);
        s->out_i32(entity->start);
        s->out_i32(entity->length);
        return;
    case tgl_message_entity_type::email:
        s->out_i32(CODE_message_entity_email);
        s->out_i32(entity->start);
        s->out_i32(entity->length);
        return;
    case tgl_message_entity_type::pre:
        s->out_i32(CODE_message_entity_pre);
        s->out_i32(entity->start);
        s->out_i32(entity->length);
        s->out_std_string(entity->text_url_or_language);
        return;
    }
    assert(false);
}

}
}
