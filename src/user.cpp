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

#include "user.h"

#include "auto/auto.h"
#include "auto/auto-skip.h"
#include "auto/auto-types.h"
#include "auto/auto-free-ds.h"
#include "auto/auto-fetch-ds.h"
#include "auto/constants.h"
#include "structures.h"

user::user(const tl_ds_user* DS_U)
    : m_id(tgl_peer_type::user, DS_LVAL(DS_U->id), DS_LVAL(DS_U->access_hash))
    , m_status(tglf_fetch_user_status(DS_U->status))
    , m_user_name(DS_STDSTR(DS_U->username))
    , m_first_name(DS_STDSTR(DS_U->first_name))
    , m_last_name(DS_STDSTR(DS_U->last_name))
    , m_phone_number(DS_STDSTR(DS_U->phone))
    , m_contact(false)
    , m_mutual_contact(false)
    , m_blocked(false)
    , m_blocked_confirmed(false)
    , m_self(false)
    , m_bot(false)
    , m_deleted(false)
    , m_official(false)
{
    if (!DS_U || DS_U->magic == CODE_user_empty) {
        return;
    }

    int32_t flags = DS_LVAL(DS_U->flags);

    set_self(flags & (1 << 10));
    set_contact(flags & (1 << 11));
    set_mutual_contact(flags & (1 << 12));
    set_deleted(flags & (1 << 13));
    set_bot(flags & (1 << 14));

    /*
    if (DS_LVAL(DS_U->flags) & (1 << 15)) {
        flags |= TGLUF_BOT_FULL_ACCESS;
    }

    if (DS_LVAL(DS_U->flags) & (1 << 16)) {
        flags |= TGLUF_BOT_NO_GROUPS;
    }*/

    set_official(flags & (1 << 17));

    if (DS_U->photo) {
        if (DS_U->photo->photo_big) {
            m_photo_big = tglf_fetch_file_location(DS_U->photo->photo_big);
        }
        if (DS_U->photo->photo_small) {
            m_photo_small = tglf_fetch_file_location(DS_U->photo->photo_small);
        }
    }
}

user::user(const tl_ds_user_full* DS_UF)
    : user(DS_UF->user)
{
    set_blocked(DS_BVAL(DS_UF->blocked));
}
