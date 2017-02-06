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

#ifndef __TGL_UNCONFIRMED_SECRET_MESSAGE_H__
#define __TGL_UNCONFIRMED_SECRET_MESSAGE_H__

#include <memory>
#include <stdint.h>
#include <string>
#include <vector>

class tgl_unconfirmed_secret_message {
public:
    virtual ~tgl_unconfirmed_secret_message() { }
    virtual int64_t message_id() const = 0;
    virtual int64_t date() const = 0;
    virtual int32_t chat_id() const = 0;
    virtual int32_t in_seq_no() const = 0;
    virtual int32_t out_seq_no() const = 0;
    virtual bool is_out_going() const = 0;
    virtual uint32_t constructor_code() const = 0;
    virtual const std::vector<std::string>& blobs() const = 0;
    virtual void append_blob(std::string&& blob) = 0;
    virtual void clear_blobs() = 0;

    static std::shared_ptr<tgl_unconfirmed_secret_message> create_default_impl(int64_t message_id,
            int64_t date, int32_t chat_id, int32_t in_seq_no, int32_t out_seq_no, bool is_out_going, uint32_t construtor_code);
};

#endif
