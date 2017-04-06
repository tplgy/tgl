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

#pragma once

#include <cstdint>
#include <string>

#include "tgl_chat.h"
#include "tgl_file_location.h"

enum class tgl_channel_participant_type
{
    admins,
    recent,
    kicked,
    bots,
};

struct tgl_channel_participant: public tgl_chat_participant
{
    bool is_editor = false;
    bool is_self = false;
    bool is_moderator = false;
    bool is_kicked = false;
};

class tgl_channel: virtual public tgl_chat
{
public:
    virtual ~tgl_channel() { }
    virtual int32_t admins_count() const = 0;
    virtual int32_t kicked_count() const = 0;
    virtual bool is_official() const = 0;
    virtual bool is_broadcast() const = 0;
};
