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

#include "tgl/tgl_transfer_manager.h"

#include <memory>
#include <map>

namespace tgl {
namespace impl {

class download_task;
class query_download_file_part;
class query_upload_file_part;
class upload_task;
class user_agent;
struct tl_ds_upload_file;

class transfer_manager: public std::enable_shared_from_this<transfer_manager>, public tgl_transfer_manager
{
public:
    transfer_manager(const std::weak_ptr<user_agent>& weak_ua, const std::string& download_directory)
        : m_user_agent(weak_ua)
        , m_download_directory(download_directory)
    { }

    virtual std::string download_directory() const override { return m_download_directory; }
    virtual bool file_exists(const tgl_file_location &location) const override;
    virtual std::string get_file_path(int64_t secret) const override;
    virtual void download_by_file_location(int64_t download_id, const tgl_file_location& location,
            int32_t file_size, const tgl_download_callback& callback) override;
    virtual void download_document(int64_t download_id, const std::shared_ptr<tgl_download_document>& document,
            const tgl_download_callback& callback) override;
    virtual void cancel_download(int64_t download_id) override;
    virtual void upload_document(const tgl_input_peer_t& to_id, int64_t message_id,
            const std::shared_ptr<tgl_upload_document>& document,
            tgl_upload_option option,
            const tgl_upload_callback& callback,
            const tgl_read_callback& read_callback,
            const tgl_upload_part_done_callback& part_done_callback,
            int32_t reply = 0) override;
    virtual void upload_profile_photo(const std::string &file_name, int32_t file_size,
            const std::function<void(bool success)>& callback,
            const tgl_read_callback& read_callback,
            const tgl_upload_part_done_callback& done_callback) override;
    virtual void upload_chat_photo(const tgl_input_peer_t& chat_id, const std::string &file_name, int32_t file_size,
            const std::function<void(bool success)>& callback,
            const tgl_read_callback& read_callback,
            const tgl_upload_part_done_callback& done_callback) override;
    virtual void upload_channel_photo(const tgl_input_peer_t& chat_id, const std::string &file_name, int32_t file_size,
            const std::function<void(bool success)>& callback,
            const tgl_read_callback& read_callback,
            const tgl_upload_part_done_callback& done_callback) override;
    virtual void cancel_upload(int64_t message_id) override;
    virtual bool is_uploading_file(int64_t message_id) const override;
    virtual bool is_downloading_file(int64_t download_id) const override;

private:
    void upload_part_finished(const std::shared_ptr<upload_task>&u, size_t part_number, bool success);

    void upload_avatar_end(const std::shared_ptr<upload_task>&, const std::function<void(bool)>& callback);
    void upload_end(const std::shared_ptr<upload_task>&);
    void upload_unencrypted_file_end(const std::shared_ptr<upload_task>&);
    void upload_encrypted_file_end(const std::shared_ptr<upload_task>&);
    void upload_thumb(const std::shared_ptr<upload_task>&);

    void upload_multiple_parts(const std::shared_ptr<upload_task>& u, size_t count);
    void upload_part(const std::shared_ptr<upload_task>&);

    void upload_document(const tgl_input_peer_t& to_id,
            int64_t message_id, int32_t avatar, int32_t reply, bool as_photo,
            const std::shared_ptr<tgl_upload_document>& document,
            const tgl_upload_callback& callback,
            const tgl_read_callback& read_callback,
            const tgl_upload_part_done_callback& part_done_callback);

    void upload_photo(const tgl_input_peer_t& chat_id, const std::string &file_name, int32_t file_size,
                      const std::function<void(bool success)>& callback,
                      const tgl_read_callback& read_callback,
                      const tgl_upload_part_done_callback& done_callback);

    void download_part_finished(const std::shared_ptr<download_task>&, size_t offset, const tl_ds_upload_file*);

    void download_multiple_parts(const std::shared_ptr<download_task>&, size_t count);
    void download_part(const std::shared_ptr<download_task>&);
    void download_end(const std::shared_ptr<download_task>&);

private:
    std::weak_ptr<user_agent> m_user_agent;
    std::string m_download_directory;
    std::map<int64_t, std::shared_ptr<download_task>> m_downloads;
    std::map<int64_t, std::shared_ptr<upload_task>> m_uploads;
};

static constexpr size_t BIG_FILE_THRESHOLD = 10 * 1024 * 1024;

}
}
