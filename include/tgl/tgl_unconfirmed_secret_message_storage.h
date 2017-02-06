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

    Copyright Topology LP 2017
*/

#ifndef __TGL_UNCONFIRMED_SECRET_MESSAGE_STORAGE_H__
#define __TGL_UNCONFIRMED_SECRET_MESSAGE_STORAGE_H__

#include "tgl_unconfirmed_secret_message.h"

#include <memory>
#include <stdint.h>
#include <vector>

class tgl_unconfirmed_secret_message_storage {
public:
    virtual ~tgl_unconfirmed_secret_message_storage() { }

    virtual void store_message(const std::shared_ptr<tgl_unconfirmed_secret_message>& message) = 0;

    virtual void update_message(const std::shared_ptr<tgl_unconfirmed_secret_message>& message) = 0;

    virtual std::vector<std::shared_ptr<tgl_unconfirmed_secret_message>>
    load_messages_by_out_seq_no(int32_t chat_id, int32_t seq_no_start, int32_t seq_no_end, bool is_out_going) = 0;

    virtual void remove_messages_by_out_seq_no(int32_t chat_id, int32_t seq_no_start, int32_t seq_no_end, bool is_out_going) = 0;
};

#endif
