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

#ifndef __TGL_USER_H__
#define __TGL_USER_H__

#include "tgl_file_location.h"
#include "tgl_peer_id.h"

#include <memory>
#include <string>

class tgl_timer;
struct tgl_message;

enum class tgl_user_online_status: int32_t {
    unknown = 0,
    online = 1,
    offline = 2,
    recent = 3,
    last_week = 4,
    last_month
};

struct tgl_user_status {
    tgl_user_online_status online;
    int64_t when;
    tgl_user_status(): online(tgl_user_online_status::unknown), when(0) { }
};

constexpr int32_t TGLUF_CONTACT = 1 << 16;
constexpr int32_t TGLUF_MUTUAL_CONTACT = 1 << 17;
constexpr int32_t TGLUF_BLOCKED = 1 << 18;
constexpr int32_t TGLUF_SELF = 1 << 19;
constexpr int32_t TGLUF_BOT = 1 << 20;
constexpr int32_t TGLUF_OFFICIAL = 1 << 3;
constexpr int32_t TGLUF_DELETED = 1 << 2;
constexpr int32_t TGLUF_MASK = TGLUF_DELETED | TGLUF_OFFICIAL | TGLUF_CONTACT
        | TGLUF_MUTUAL_CONTACT | TGLUF_BLOCKED | TGLUF_SELF | TGLUF_BOT | TGLUF_OFFICIAL;

struct tgl_user {
    tgl_input_peer_t id;
    int32_t flags;
    struct tgl_user_status status;
    std::string username;
    std::string firstname;
    std::string lastname;
    std::string phone;

    tgl_user()
        : flags(0)
    { }

    bool is_contact() const { return flags & TGLUF_CONTACT; }
    bool is_mutual_contact() const { return flags & TGLUF_MUTUAL_CONTACT; }
    bool is_blocked() const { return flags & TGLUF_BLOCKED; }
    bool is_self() const { return flags & TGLUF_SELF; }
    bool is_bot() const { return flags & TGLUF_BOT; }
    bool is_deleted() const { return flags & TGLUF_DELETED; }
    bool is_official() const { return flags & TGLUF_MASK; }
};

#endif
