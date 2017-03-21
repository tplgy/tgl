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

#pragma once

#include "query.h"

namespace tgl {
namespace impl {

class download_task;
struct tl_ds_upload_file;

class query_download_file_part: public query
{
public:
    query_download_file_part(user_agent& ua, const std::shared_ptr<download_task>& download,
            const std::function<void(const tl_ds_upload_file*)>& callback);
    virtual void on_answer(void* answer) override;
    virtual int on_error(int error_code, const std::string& error_string) override;
    virtual double timeout_interval() const override { return 20.0; }
    virtual void on_connection_status_changed(tgl_connection_status status) override;
    virtual void will_send() override;
    virtual bool is_file_transfer() const override { return true; }

private:
    bool download_finished() const;

private:
    std::shared_ptr<download_task> m_download;
    std::function<void(const tl_ds_upload_file*)> m_callback;
};

}
}
