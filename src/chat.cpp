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

#include "chat.h"

#include "auto/auto.h"
#include "auto/auto-skip.h"
#include "auto/auto-types.h"
#include "auto/auto-free-ds.h"
#include "auto/auto-fetch-ds.h"
#include "auto/constants.h"
#include "channel.h"
#include "structures.h"

#include <cassert>

namespace tgl {
namespace impl {

std::shared_ptr<chat> chat::create(const tl_ds_chat* DS_C)
{
    if (!DS_C) {
        return std::shared_ptr<chat>(new chat(nullptr));
    }

    if (DS_C->magic == CODE_channel || DS_C->magic == CODE_channel_forbidden) {
        return std::shared_ptr<chat>(new channel(DS_C));
    }

    return std::shared_ptr<chat>(new chat(DS_C));
}

chat::chat(const tl_ds_chat* DS_C, chat::dont_check_magic)
    : m_date(0)
    , m_participants_count(0)
    , m_is_creator(false)
    , m_is_kicked(false)
    , m_is_left(false)
    , m_is_admins_enabled(false)
    , m_is_deactivated(false)
    , m_is_admin(false)
    , m_is_editor(false)
    , m_is_moderator(false)
    , m_is_verified(false)
    , m_is_mega_group(false)
    , m_is_restricted(false)
    , m_is_forbidden(false)
{
    if (!DS_C || DS_C->magic == CODE_chat_empty) {
        return;
    }

    m_id = tgl_input_peer_t(tgl_peer_type::chat, DS_LVAL(DS_C->id), DS_LVAL(DS_C->access_hash));
    m_date = DS_LVAL(DS_C->date);
    m_participants_count = DS_LVAL(DS_C->participants_count);

    m_is_editor = DS_BOOL(DS_C->editor);
    m_is_moderator = DS_BOOL(DS_C->moderator);
    m_is_verified = DS_BOOL(DS_C->verified);
    m_is_mega_group = DS_BOOL(DS_C->megagroup);
    m_is_restricted = DS_BOOL(DS_C->restricted);
    m_is_forbidden = DS_C->magic == CODE_chat_forbidden;
    m_title = DS_STDSTR(DS_C->title);
    m_user_name = DS_STDSTR(DS_C->username);

    int32_t flags = DS_LVAL(DS_C->flags);
    m_is_creator = flags & 1;
    m_is_kicked = flags & 2;
    m_is_left = flags & 4;
    m_is_admins_enabled = flags & 8;
    m_is_admin = flags & 16;
    m_is_deactivated = flags & 32;

    if (DS_C->photo) {
        m_photo_big = tglf_fetch_file_location(DS_C->photo->photo_big);
        m_photo_small = tglf_fetch_file_location(DS_C->photo->photo_small);
    }
}

chat::chat(const tl_ds_chat* DS_C)
    : chat(DS_C, chat::dont_check_magic())
{
    if (empty()) {
        return;
    }

    assert(DS_C->magic == CODE_chat);
}

}
}
