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

    Copyright Vitaly Valtman 2014-2015
    Copyright Topology LP 2016-2017
*/

#include "upload_task.h"

#include <cstring>

upload_task::upload_task()
    : size(0)
    , offset(0)
    , part_num(0)
    , part_size(0)
    , id(0)
    , thumb_id(0)
    , to_id()
    , doc_type(tgl_document_type::unknown)
    , as_photo(false)
    , animated(false)
    , avatar(0)
    , reply(0)
    , width(0)
    , height(0)
    , duration(0)
    , thumb_width(0)
    , thumb_height(0)
    , message_id(0)
    , status(tgl_upload_status::waiting)
    , at_EOF(false)
    , m_cancel_requested(false)
{
}

upload_task::~upload_task()
{
    // For security reasion.
    memset(iv.data(), 0, iv.size());
    memset(init_iv.data(), 0, init_iv.size());
    memset(key.data(), 0, key.size());
}

void upload_task::set_status(tgl_upload_status status, const std::shared_ptr<tgl_message>& message)
{
    this->status = status;
    if (callback) {
        callback(status, message, offset);
    }
}

bool upload_task::check_cancelled()
{
    if (!m_cancel_requested && status != tgl_upload_status::cancelled) {
        return false;
    }
    set_status(tgl_upload_status::cancelled);
    return true;
}
