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

#include <cassert>
#include <memory>

#include "auto/auto-types.h"
#include "tools.h"
#include "tgl/tgl_bot.h"
#include "tgl/tgl_chat.h"
#include "tgl/tgl_channel.h"
#include "tgl/tgl_message_media.h"
#include "tgl/tgl_user.h"

namespace tgl {
namespace impl {

class user_agent;

void tglf_fetch_chat_participants(const std::shared_ptr<tgl_chat>& C, const tl_ds_chat_participants* DS_CP);

tgl_file_location tglf_fetch_file_location(const tl_ds_file_location* DS_FL);

std::shared_ptr<tgl_photo> tglf_fetch_alloc_photo(const tl_ds_photo* DS_P);
std::shared_ptr<tgl_webpage> tglf_fetch_alloc_webpage(const tl_ds_web_page* DS_W);
std::shared_ptr<tgl_photo_size> tglf_fetch_photo_size(const tl_ds_photo_size* DS_PS);

}
}
