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

#ifndef __TGL_TYPING_STATUS_H__
#define __TGL_TYPING_STATUS_H__

#include <cassert>
#include <iostream>
#include <string>

enum class tgl_typing_status {
    none,
    typing,
    cancel,
    record_video,
    upload_video,
    record_audio,
    upload_audio,
    upload_photo,
    upload_document,
    geo,
    choose_contact,
};

inline static std::string to_string(tgl_typing_status status)
{
    switch (status) {
    case tgl_typing_status::none:
        return "none";
    case tgl_typing_status::typing:
        return "typing";
    case tgl_typing_status::cancel:
        return "cancel";
    case tgl_typing_status::record_video:
        return "record_video";
    case tgl_typing_status::upload_video:
        return "upload_video";
    case tgl_typing_status::record_audio:
        return "record_audio";
    case tgl_typing_status::upload_audio:
        return "upload_audio";
    case tgl_typing_status::upload_photo:
        return "upload_photo";
    case tgl_typing_status::upload_document:
        return "upload_document";
    case tgl_typing_status::geo:
        return "geo";
    case tgl_typing_status::choose_contact:
        return "choose_contact";
    default:
        assert(false);
        return "unknown typing status";
    }
}

inline std::ostream& operator<<(std::ostream& os, tgl_typing_status status)
{
    os << to_string(status);
    return os;
}

#endif
