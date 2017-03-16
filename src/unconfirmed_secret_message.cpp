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

#include "unconfirmed_secret_message.h"

std::shared_ptr<tgl_unconfirmed_secret_message> tgl_unconfirmed_secret_message::create_default_impl(int64_t message_id,
        int64_t date, int32_t chat_id, int32_t in_seq_no, int32_t out_seq_no, bool is_out_going, uint32_t constructor_code)
{
    return std::make_shared<tgl::impl::unconfirmed_secret_message>(
        message_id, date, chat_id, in_seq_no, out_seq_no, is_out_going, constructor_code);
}
