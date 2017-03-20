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

#include "peer_id.h"

#include "auto/auto.h"
#include "auto/auto-types.h"
#include "auto/constants.h"

#include <cassert>

namespace tgl {
namespace impl {

tgl_peer_id_t create_peer_id(const tl_ds_peer* DS_P)
{
    switch (DS_P->magic) {
    case CODE_peer_user:
        return tgl_peer_id_t(tgl_peer_type::user, DS_LVAL(DS_P->user_id));
    case CODE_peer_chat:
        return tgl_peer_id_t(tgl_peer_type::chat, DS_LVAL(DS_P->chat_id));
    case CODE_peer_channel:
        return tgl_peer_id_t(tgl_peer_type::channel, DS_LVAL(DS_P->channel_id));
    default:
        assert(false);
        return tgl_peer_id_t();
    }
}

}
}

