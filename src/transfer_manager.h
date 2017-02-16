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

#ifndef __TRANSFER_MANAGER_H__
#define __TRANSFER_MANAGER_H__

#include "tgl/tgl_transfer_manager.h"

#include <map>

class download_task;
class query_download;
class query_upload_part;
class upload_task;

class transfer_manager: public tgl_transfer_manager
{
public:
    transfer_manager(const std::string& download_directory)
        : m_download_directory(download_directory)
    { }

    virtual std::string download_directory() const override { return m_download_directory; }
    virtual bool file_exists(const tgl_file_location &location) const override;
    virtual std::string get_file_path(int64_t secret) const override;
    virtual void download_by_file_location(int64_t download_id, const tgl_file_location& location,
            int32_t file_size, const tgl_download_callback& callback) override;
    virtual void download_document(int64_t download_id, const std::shared_ptr<tgl_document>& document,
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
    friend class query_download;
    friend class query_upload_part;

    int download_on_answer(const std::shared_ptr<query_download>& q, void* answer);
    int download_on_error(const std::shared_ptr<query_download>& q, int error_code, const std::string &error);
    int upload_part_on_answer(const std::shared_ptr<query_upload_part>& q, void* answer);

    void upload_avatar_end(const std::shared_ptr<upload_task>&, const std::function<void(bool)>& callback);
    void upload_end(const std::shared_ptr<upload_task>&, const tgl_upload_callback& callback);
    void upload_unencrypted_file_end(const std::shared_ptr<upload_task>&, const tgl_upload_callback& callback);
    void upload_encrypted_file_end(const std::shared_ptr<upload_task>&, const tgl_upload_callback& callback);
    void upload_thumb(const std::shared_ptr<upload_task>&,
            const tgl_upload_callback& callback,
            const tgl_read_callback& read_callback,
            const tgl_upload_part_done_callback& done_callback);

    void upload_part(
            const std::shared_ptr<upload_task>&,
            const tgl_upload_callback& callback,
            const tgl_read_callback& read_callback,
            const tgl_upload_part_done_callback& done_callback);

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

    void download_document(const std::shared_ptr<download_task>&, const std::string& mime_type,
             const tgl_download_callback& callback);

    void download_next_part(const std::shared_ptr<download_task>&, const tgl_download_callback& callback);
    void end_download(const std::shared_ptr<download_task>&, const tgl_download_callback& callback);

    std::map<int64_t, std::shared_ptr<download_task>> m_downloads;
    std::map<int64_t, std::shared_ptr<upload_task>> m_uploads;
    std::string m_download_directory;
};

static constexpr size_t BIG_FILE_THRESHOLD = 10 * 1024 * 1024;

#endif
