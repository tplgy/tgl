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

#ifndef __TGL_MESSAGE_H__
#define __TGL_MESSAGE_H__

#include "tgl_message_action.h"
#include "tgl_message_entity.h"
#include "tgl_message_media.h"
#include "tgl_peer_id.h"

#include <cstdint>
#include <memory>
#include <vector>

struct tgl_message_reply_markup {
  int flags;
  std::vector<std::vector<std::string>> button_matrix;
  tgl_message_reply_markup(): flags(0) { }
};

struct tgl_message {
    int64_t server_id;
    int64_t random_id;
    int32_t flags;
    int32_t reply_id;
    int64_t fwd_date;
    int64_t date;
    int64_t permanent_id;
    tgl_peer_id_t fwd_from_id;
    tgl_peer_id_t from_id;
    tgl_input_peer_t to_id;
    std::vector<std::shared_ptr<tgl_message_entity>> entities;
    std::shared_ptr<tgl_message_reply_markup> reply_markup;
    std::shared_ptr<tgl_message_action> action;
    std::shared_ptr<tgl_message_media> media;
    std::string message;
    tgl_message()
        : server_id(0)
        , random_id(0)
        , flags(0)
        , reply_id(0)
        , fwd_date(0)
        , date(0)
        , permanent_id(0)
        , fwd_from_id()
        , from_id()
        , to_id()
        , action(std::make_shared<tgl_message_action_none>())
        , media(std::make_shared<tgl_message_media_none>())
    { }
};

struct tgl_secret_message {
    std::shared_ptr<tgl_message> message;
    tgl_input_peer_t chat_id;
    int32_t layer;
    int32_t in_seq_no;
    int32_t out_seq_no;

    tgl_secret_message()
        : layer(-1)
        , in_seq_no(-1)
        , out_seq_no(-1)
    { }

    tgl_secret_message(const std::shared_ptr<tgl_message>& message, const tgl_input_peer_t& chat_id, int32_t layer, int32_t in_seq_no, int32_t out_seq_no)
        : message(message)
        , chat_id(chat_id)
        , layer(layer)
        , in_seq_no(in_seq_no)
        , out_seq_no(out_seq_no)
    { }
};

#endif
