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

struct tgl_user {
    tgl_input_peer_t id;
    int32_t flags;
    int64_t access_hash;
    struct tgl_user_status status;
    std::string username;
    std::string firstname;
    std::string lastname;
    std::string phone;
    tgl_user(): flags(0), access_hash(0) { }
};

#endif
