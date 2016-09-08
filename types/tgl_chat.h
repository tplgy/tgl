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

#ifndef __TGL_CHAT_H__
#define __TGL_CHAT_H__

#include <cstdint>
#include <string>
#include <vector>

#include "tgl_file_location.h"
#include "tgl_peer_id.h"

struct tgl_chat_user {
    int32_t user_id;
    int32_t inviter_id;
    int32_t date;
    tgl_chat_user(): user_id(0), inviter_id(0), date(0) { }
};

struct tgl_chat {
    tgl_input_peer_t id;
    int64_t date;
    int32_t participants_count;
    bool creator;
    bool kicked;
    bool left;
    bool admins_enabled;
    bool deactivated;
    bool admin;
    bool editor;
    bool moderator;
    bool verified;
    bool megagroup;
    bool restricted;
    std::string username;
    tgl_file_location photo_big;
    tgl_file_location photo_small;
    std::string title;
    tgl_chat()
        : date(0)
        , participants_count(0)
        , creator(false)
        , kicked(false)
        , left(false)
        , admins_enabled(false)
        , deactivated(false)
        , admin(false)
        , editor(false)
        , moderator(false)
        , verified(false)
        , megagroup(false)
        , restricted(false)
    { }
};

#endif
