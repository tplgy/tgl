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

#pragma once

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

struct tgl_user {
    tgl_input_peer_t id;
    struct tgl_user_status status;
    std::string username;
    std::string firstname;
    std::string lastname;
    std::string phone;

    tgl_user()
        : m_contact(false)
        , m_mutual_contact(false)
        , m_blocked(false)
        , m_blocked_confirmed(false)
        , m_self(false)
        , m_bot(false)
        , m_deleted(false)
        , m_official(false)
    { }

    bool is_contact() const { return m_contact; }
    bool is_mutual_contact() const { return m_mutual_contact; }
    bool is_blocked() const { return m_blocked; }
    bool is_blocked_confirmed() const { return m_blocked_confirmed; }
    bool is_self() const { return m_self; }
    bool is_bot() const { return m_bot; }
    bool is_deleted() const { return m_deleted; }
    bool is_official() const { return m_official; }

    tgl_user& set_contact(bool b) { m_contact = b; return *this; }
    tgl_user& set_mutual_contact(bool b) { m_mutual_contact = b; return *this; }
    tgl_user& set_blocked(bool b) { m_blocked = b; m_blocked_confirmed = true; return *this; }
    tgl_user& set_self(bool b) { m_self = b; return *this; }
    tgl_user& set_bot(bool b) { m_bot = b; return *this; }
    tgl_user& set_deleted(bool b) { m_deleted = b; return *this; }
    tgl_user& set_official(bool b) { m_official = b; return *this; }

private:
    bool m_contact;
    bool m_mutual_contact;
    bool m_blocked;
    bool m_blocked_confirmed;
    bool m_self;
    bool m_bot;
    bool m_deleted;
    bool m_official;
};
