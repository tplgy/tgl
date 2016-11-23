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

#ifndef __TGL_CHANNEL_H__
#define __TGL_CHANNEL_H__

#include <cstdint>
#include <string>

#include "types/tgl_chat.h"
#include "types/tgl_file_location.h"

enum class tgl_channel_participant_type
{
    admins,
    recent,
    kicked,
    bots,
};

struct tgl_channel_participant: public tgl_chat_participant
{
};

struct tgl_channel: public tgl_chat {
    int32_t admins_count;
    int32_t kicked_count;
    int32_t pts;
    int32_t mute_until;
    bool official;
    bool broadcast;
    bool diff_locked;
    std::string about;

    tgl_channel()
        : admins_count(0)
        , kicked_count(0)
        , pts(0)
        , mute_until(0)
        , official(false)
        , broadcast(false)
        , diff_locked(false)
    { }
};

#endif
