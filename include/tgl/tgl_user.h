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

#include <string>

enum class tgl_user_online_status: int32_t
{
    unknown = 0,
    online = 1,
    offline = 2,
    recent = 3,
    last_week = 4,
    last_month
};

struct tgl_user_status
{
    tgl_user_online_status online = tgl_user_online_status::unknown;
    int64_t when = 0;
};

class tgl_user
{
public:
    virtual ~tgl_user() { }
    virtual const tgl_input_peer_t& id() = 0;
    virtual const tgl_user_status& status() = 0;
    virtual const std::string& user_name() = 0;
    virtual const std::string& first_name() = 0;
    virtual const std::string& last_name() = 0;
    virtual const std::string& phone_number() = 0;
    virtual bool is_contact() const = 0;
    virtual bool is_mutual_contact() const = 0;
    virtual bool is_blocked() const = 0;
    virtual bool is_blocked_confirmed() const = 0;
    virtual bool is_self() const = 0;
    virtual bool is_bot() const = 0;
    virtual bool is_deleted() const = 0;
    virtual bool is_official() const = 0;
};
