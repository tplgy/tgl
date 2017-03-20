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

#include "typing_status.h"

#include "auto/auto.h"
#include "auto/auto_types.h"
#include "auto/constants.h"
#include <cassert>

namespace tgl {
namespace impl {

tgl_typing_status create_typing_status(const tl_ds_send_message_action* DS_SMA)
{
    if (!DS_SMA) {
        return tgl_typing_status::none;
    }
    switch (DS_SMA->magic) {
    case CODE_send_message_typing_action:
        return tgl_typing_status::typing;
    case CODE_send_message_cancel_action:
        return tgl_typing_status::cancel;
    case CODE_send_message_record_video_action:
        return tgl_typing_status::record_video;
    case CODE_send_message_upload_video_action:
        return tgl_typing_status::upload_video;
    case CODE_send_message_record_audio_action:
        return tgl_typing_status::record_audio;
    case CODE_send_message_upload_audio_action:
        return tgl_typing_status::upload_audio;
    case CODE_send_message_upload_photo_action:
        return tgl_typing_status::upload_photo;
    case CODE_send_message_upload_document_action:
        return tgl_typing_status::upload_document;
    case CODE_send_message_geo_location_action:
        return tgl_typing_status::geo;
    case CODE_send_message_choose_contact_action:
        return tgl_typing_status::choose_contact;
    default:
        assert(false);
        return tgl_typing_status::none;
    }
}

}
}
