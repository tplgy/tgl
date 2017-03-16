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

#include "query_download_file_part.h"

#include "download_task.h"
#include "tgl/tgl_log.h"

#include <cassert>

namespace tgl {
namespace impl {

query_download_file_part::query_download_file_part(const std::shared_ptr<download_task>& download,
        const std::function<void(const tl_ds_upload_file*)>& callback)
    : query("download", TYPE_TO_PARAM(upload_file))
    , m_download(download)
    , m_callback(callback)
{
}

void query_download_file_part::on_answer(void* D)
{
    if (m_callback) {
        m_callback(static_cast<tl_ds_upload_file*>(D));
    }
}

int query_download_file_part::on_error(int error_code, const std::string& error_string)
{
    TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
    if (m_callback) {
        m_callback(nullptr);
    }
    return 0;
}

void query_download_file_part::on_connection_status_changed(tgl_connection_status status)
{
    if (download_finished()) {
        return;
    }

    tgl_download_status download_status = m_download->status;

    switch (status) {
    case tgl_connection_status::connecting:
        download_status = tgl_download_status::connecting;
        break;
    case tgl_connection_status::disconnected:
    case tgl_connection_status::closed:
    case tgl_connection_status::connected:
        download_status = tgl_download_status::waiting;
        break;
    }

    m_download->set_status(download_status);
}

void query_download_file_part::will_send()
{
    if (download_finished()) {
        return;
    }
    m_download->set_status(tgl_download_status::downloading);
}

bool query_download_file_part::download_finished() const
{
    return m_download->status == tgl_download_status::succeeded
            || m_download->status == tgl_download_status::failed
            || m_download->status == tgl_download_status::cancelled;
}

}
}
