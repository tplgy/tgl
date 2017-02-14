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

#include "query_upload_file_part.h"

query_upload_file_part::query_upload_file_part(const std::shared_ptr<upload_task>& u,
        const std::function<void(bool success)>& callback)
    : query("upload part", TYPE_TO_PARAM(bool))
    , m_upload(u)
    , m_callback(callback)
{
}

void query_upload_file_part::on_answer(void*)
{
    m_upload->offset = m_upload->part_num * m_upload->part_size;
    if (m_upload->offset > m_upload->size) {
        m_upload->offset = m_upload->size;
    }

    if (m_upload->status == tgl_upload_status::waiting || m_upload->status == tgl_upload_status::connecting) {
        m_upload->set_status(tgl_upload_status::uploading);
    }

    if (m_callback) {
        m_callback(true);
    }
}

int query_upload_file_part::on_error(int error_code, const std::string& error_string)
{
    TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
    m_upload->set_status(tgl_upload_status::failed);
    if (m_callback) {
        m_callback(false);
    }
    return 0;
}

double query_upload_file_part::timeout_interval() const
{
    // We upload part of size 512KB. If the user has 512Kbps upload
    // speed that would be at least 8 seconds. Considering not everyone gets
    // full claimed speed we double the time needed for the speeed of 512Kbps.
    // It turns out the time is 16 seconds. And then we add a little bit of
    // offset of 4 seconds.
    return 20;
}

void query_upload_file_part::on_connection_status_changed(tgl_connection_status status)
{
    if (upload_finished()) {
        return;
    }

    tgl_upload_status upload_status = m_upload->status;

    switch (status) {
    case tgl_connection_status::connecting:
        upload_status = tgl_upload_status::connecting;
        break;
    case tgl_connection_status::disconnected:
    case tgl_connection_status::closed:
    case tgl_connection_status::connected:
        upload_status = tgl_upload_status::waiting;
        break;
    }

    m_upload->set_status(upload_status);
}

void query_upload_file_part::will_send()
{
    if (upload_finished()) {
        return;
    }
    m_upload->set_status(tgl_upload_status::uploading);
}

bool query_upload_file_part::upload_finished() const
{
    return m_upload->status == tgl_upload_status::succeeded
            || m_upload->status == tgl_upload_status::failed
            || m_upload->status == tgl_upload_status::cancelled;
}
