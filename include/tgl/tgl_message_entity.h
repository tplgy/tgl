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

#ifndef __TGL_MESSAGE_ENTITY_H__
#define __TGL_MESSAGE_ENTITY_H__

#include <cstdint>
#include <string>

enum class tgl_message_entity_type {
    unknown,
    mention,
    hashtag,
    bot_command,
    url,
    email,
    bold,
    italic,
    code,
    pre,
    text_url
};

struct tgl_message_entity {
    tgl_message_entity_type type;
    int32_t start;
    int32_t length;
    std::string text_url;
    tgl_message_entity()
        : type(tgl_message_entity_type::unknown)
        , start(0)
        , length(0)
    { }
};

#endif
