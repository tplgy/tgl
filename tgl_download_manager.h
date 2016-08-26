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
    Copyright Topology LP 2016
*/

#ifndef TGL_DOWNLOAD_MANAGER_H
#define TGL_DOWNLOAD_MANAGER_H

#include "types/tgl_file_location.h"
#include "types/tgl_peer_id.h"
#include "types/tgl_message.h"

#include <array>
#include <cassert>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <string.h>
#include <vector>

struct tgl_document;
struct tgl_encr_document;
struct tgl_photo_size;
struct tgl_message;
struct tgl_photo;
struct tl_ds_storage_file_type;
struct tgl_upload;
struct tgl_download;
class query_download;
class query_upload_part;

enum class tgl_download_status
{
    downloading,
    succeeded,
    failed,
    cancelled,
};

inline static std::string to_string(tgl_download_status status)
{
    switch (status) {
    case tgl_download_status::downloading:
        return "downloading";
    case tgl_download_status::succeeded:
        return "succeeded";
    case tgl_download_status::failed:
        return "failed";
    case tgl_download_status::cancelled:
        return "cancelled";
    default:
        assert(false);
        return "unknown";
    }
}

inline static std::ostream& operator<<(std::ostream& oss, tgl_download_status status)
{
    oss << to_string(status);
    return oss;
}

enum class tgl_upload_status
{
    uploading,
    succeeded,
    failed,
    cancelled,
};

inline static std::string to_string(tgl_upload_status status)
{
    switch (status) {
    case tgl_upload_status::uploading:
        return "uploading";
    case tgl_upload_status::succeeded:
        return "succeeded";
    case tgl_upload_status::failed:
        return "failed";
    case tgl_upload_status::cancelled:
        return "cancelled";
    default:
        assert(false);
        return "unknown";
    }
}

inline static std::ostream& operator<<(std::ostream& oss, tgl_upload_status status)
{
    oss << to_string(status);
    return oss;
}

using tgl_download_callback = std::function<void(tgl_download_status status, const std::string& file_name, float progress)>;
using tgl_upload_callback = std::function<void(tgl_upload_status status, const std::shared_ptr<tgl_message>& message, float progress)>;
using tgl_read_callback = std::function<std::shared_ptr<std::vector<uint8_t>>(uint32_t chunk_size)>;
using tgl_upload_part_done_callback = std::function<void()>;

class tgl_download_manager
{
public:
    tgl_download_manager(std::string download_directory);
    std::string download_directory() { return m_download_directory; }

    bool file_exists(const tgl_file_location &location);

    std::string get_file_path(int64_t secret);  // parameter is either secret or access hash depending on file type

    int32_t download_encr_document(const std::shared_ptr<tgl_encr_document>& document, const tgl_download_callback& callback);
    int32_t download_audio(const std::shared_ptr<tgl_document>& document, const tgl_download_callback& callback);
    int32_t download_video(const std::shared_ptr<tgl_document>& document, const tgl_download_callback& callback);
    int32_t download_document_thumb(const std::shared_ptr<tgl_document>& document, const tgl_download_callback& callback);
    int32_t download_photo(const std::shared_ptr<tgl_photo>& photo, const tgl_download_callback& callback);
    int32_t download_by_photo_size(const std::shared_ptr<tgl_photo_size>& photo_size, const tgl_download_callback& callback);
    int32_t download_by_file_location(const tgl_file_location& location, int32_t file_size, const tgl_download_callback& callback);
    int32_t download_document(const std::shared_ptr<tgl_document>& document, const tgl_download_callback& callback);

    void cancel_download(int32_t download_id);

    void upload_document(const tgl_input_peer_t& to_id, int64_t message_id,
            const std::string& file_name, int32_t file_size, int32_t width, int32_t height, int32_t duration, const std::string& caption,
            const std::vector<uint8_t>& thumb_data, int32_t thumb_width, int32_t thumb_height, uint64_t flags,
            const tgl_upload_callback& callback, const tgl_read_callback& read_callback, const tgl_upload_part_done_callback& done_callback);
    void cancel_upload(int64_t message_id);

    // sets self profile photo
    // server will cut central square from this photo
    void set_profile_photo(const std::string &file_name, int32_t file_size,
                           const std::function<void(bool success)>& callback,
                           const tgl_read_callback& read_callback,
                           const tgl_upload_part_done_callback& done_callback);
    void set_chat_photo(const tgl_input_peer_t& chat_id, const std::string &file_name, int32_t file_size,
                        const std::function<void(bool success)>& callback,
                        const tgl_read_callback& read_callback,
                        const tgl_upload_part_done_callback& done_callback);

private:
    friend class query_download;
    friend class query_upload_part;

    // Callbacks
    int download_on_answer(const std::shared_ptr<query_download>& q, void* answer);
    int download_on_error(const std::shared_ptr<query_download>& q, int error_code, const std::string &error);
    int upload_part_on_answer(const std::shared_ptr<query_upload_part>& q, void* answer);

    void upload_avatar_end(const std::shared_ptr<tgl_upload>&, const std::function<void(bool)>& callback);
    void upload_end(const std::shared_ptr<tgl_upload>&, const tgl_upload_callback& callback);
    void upload_unencrypted_file_end(const std::shared_ptr<tgl_upload>&, const tgl_upload_callback& callback);
    void upload_encrypted_file_end(const std::shared_ptr<tgl_upload>&, const tgl_upload_callback& callback);
    void upload_thumb(const std::shared_ptr<tgl_upload>&,
            const tgl_upload_callback& callback,
            const tgl_read_callback& read_callback,
            const tgl_upload_part_done_callback& done_callback);

    void upload_part(const std::shared_ptr<tgl_upload>&,
            const tgl_upload_callback& callback,
            const tgl_read_callback& read_callback,
            const tgl_upload_part_done_callback& done_callback);

    void upload_document(const tgl_input_peer_t& to_id, int64_t message_id, const std::string &file_name, int32_t file_size,
            int32_t avatar, int32_t width, int32_t height, int32_t duration,
            const std::string& caption, uint64_t flags,
            const std::vector<uint8_t>& thumb_data, int thumb_width, int thumb_height,
            const tgl_upload_callback& callback,
            const tgl_read_callback& read_callback,
            const tgl_upload_part_done_callback& done_callback);

    int32_t download_document(const std::shared_ptr<tgl_document>& document, const std::shared_ptr<tgl_download>&,
             const tgl_download_callback& callback);

    void begin_download(const std::shared_ptr<tgl_download>&);
    void download_next_part(const std::shared_ptr<tgl_download>&, const tgl_download_callback& callback);
    void end_download(const std::shared_ptr<tgl_download>&, const tgl_download_callback& callback);

    std::map<int32_t, std::shared_ptr<tgl_download>> m_downloads;
    std::map<int64_t, std::shared_ptr<tgl_upload>> m_uploads;
    std::string m_download_directory;
};

#endif // TGL_DOWNLOAD_MANAGER_H
