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

#include "channel.h"

#include "auto/auto.h"
#include "auto/auto-skip.h"
#include "auto/auto-types.h"
#include "auto/auto-free-ds.h"
#include "auto/auto-fetch-ds.h"
#include "auto/constants.h"
#include "structures.h"

#include <cassert>

namespace tgl {
namespace impl {

std::shared_ptr<channel> channel::create_bare(const tgl_input_peer_t& id)
{
    return std::shared_ptr<channel>(new channel(id));
}

channel::channel(const tgl_input_peer_t& id)
    : chat(id)
    , m_admins_count(0)
    , m_kicked_count(0)
    , m_pts(0)
    , m_is_official(false)
    , m_is_broadcast(false)
    , m_is_diff_locked(false)
{
}

channel::channel(const tl_ds_chat* DS_C) throw(std::runtime_error)
    : chat(DS_C, chat::dont_check_magic())
    , m_admins_count(0)
    , m_kicked_count(0)
    , m_pts(0)
    , m_is_official(false)
    , m_is_broadcast(false)
    , m_is_diff_locked(false)
{
    assert(DS_C->magic == CODE_channel || DS_C->magic == CODE_channel_forbidden);

    m_id = tgl_input_peer_t(tgl_peer_type::channel, DS_LVAL(DS_C->id), DS_LVAL(DS_C->access_hash));
    m_is_forbidden = DS_C->magic == CODE_channel_forbidden;

    int32_t flags = DS_LVAL(DS_C->flags);
    m_is_creator = flags & 1;
    m_is_kicked = flags & 2;
    m_is_left = flags & 4;
    m_is_verified = flags & 7;
    m_is_editor = flags & 8;
    m_is_restricted = flags & 9;
    m_is_moderator = flags & 16;
    m_is_broadcast = flags & 32;
    m_is_official = flags & 128;
    m_is_mega_group = flags & 256;
}

}
}
