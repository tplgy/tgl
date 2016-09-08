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

struct tgl_channel: public tgl_chat {
    int64_t access_hash;
    int32_t participants_count;
    int32_t admins_count;
    int32_t kicked_count;
    int32_t pts;
    bool official;
    bool broadcast;
    bool diff_locked;
    std::string about;

    tgl_channel()
        : access_hash(0)
        , participants_count(0)
        , admins_count(0)
        , kicked_count(0)
        , pts(0)
        , official(false)
        , broadcast(false)
        , diff_locked(false)
    { }
};

#endif
