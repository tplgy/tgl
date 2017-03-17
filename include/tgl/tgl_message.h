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

#include "tgl_message_action.h"
#include "tgl_message_entity.h"
#include "tgl_message_media.h"
#include "tgl_peer_id.h"

#include <cstdint>
#include <memory>
#include <vector>

struct tgl_message_reply_markup
{
    int32_t flags = 0;
    std::vector<std::vector<std::string>> button_matrix;
};

class tgl_message
{
public:
    virtual ~tgl_message() { }
    virtual int64_t id() const = 0;
    virtual int32_t reply_id() const = 0;
    virtual int64_t forward_date() const = 0;
    virtual int64_t date() const = 0;
    virtual int32_t sequence_number() const = 0;
    virtual const tgl_peer_id_t& forward_from_id() const = 0;
    virtual const tgl_peer_id_t& from_id() const = 0;
    virtual const tgl_input_peer_t& to_id() const = 0;
    virtual const std::string text() const = 0;
    virtual const std::shared_ptr<tgl_message_media>& media() const = 0;
    virtual const std::shared_ptr<tgl_message_action>& action() const = 0;
    virtual const std::vector<std::shared_ptr<tgl_message_entity>>& entities() const = 0;
    virtual const std::shared_ptr<tgl_message_reply_markup>& reply_markup() const = 0;
    virtual bool is_unread() const = 0;
    virtual bool is_outgoing() const = 0;
    virtual bool is_mention() const = 0;
    virtual bool is_pending() const = 0;
    virtual bool is_service() const = 0;
    virtual bool is_send_failed() const = 0;
    virtual bool is_history() const = 0;
};
