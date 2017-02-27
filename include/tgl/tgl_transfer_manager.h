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

#ifndef __TGL_TRANSFER_MANAGER_H__
#define __TGL_TRANSFER_MANAGER_H__

#include "tgl_file_location.h"
#include "tgl_peer_id.h"
#include "tgl_message.h"

#include <cassert>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

struct tgl_document;

enum class tgl_download_status
{
    waiting,
    connecting,
    downloading,
    succeeded,
    failed,
    cancelled,
};

inline static std::string to_string(tgl_download_status status)
{
    switch (status) {
    case tgl_download_status::waiting:
        return "waiting";
    case tgl_download_status::connecting:
        return "connecting";
    case tgl_download_status::downloading:
        return "downloading";
    case tgl_download_status::succeeded:
        return "succeeded";
    case tgl_download_status::failed:
        return "failed";
    case tgl_download_status::cancelled:
        return "cancelled";
    }

    assert(false);
    return "unknown";
}

inline static std::ostream& operator<<(std::ostream& os, tgl_download_status status)
{
    os << to_string(status);
    return os;
}

enum class tgl_upload_status
{
    waiting,
    connecting,
    uploading,
    succeeded,
    failed,
    cancelled,
};

inline static std::string to_string(tgl_upload_status status)
{
    switch (status) {
    case tgl_upload_status::waiting:
        return "waiting";
    case tgl_upload_status::connecting:
        return "connecting";
    case tgl_upload_status::uploading:
        return "uploading";
    case tgl_upload_status::succeeded:
        return "succeeded";
    case tgl_upload_status::failed:
        return "failed";
    case tgl_upload_status::cancelled:
        return "cancelled";
    }

    assert(false);
    return "unknown";
}

inline static std::ostream& operator<<(std::ostream& oss, tgl_upload_status status)
{
    oss << to_string(status);
    return oss;
}

enum class tgl_upload_option
{
    as_photo,
    as_document,
    auto_detect_document_type, // implies as_document
};

struct tgl_upload_document
{
    tgl_document_type type;
    bool is_animated;
    size_t file_size;
    int32_t width;
    int32_t height;
    int32_t duration;
    int32_t thumb_width;
    int32_t thumb_height;
    std::string file_name;
    std::string caption;
    std::vector<uint8_t> thumb_data;

    tgl_upload_document()
        : type(tgl_document_type::unknown)
        , is_animated(false)
        , file_size(0)
        , width(0)
        , height(0)
        , duration(0)
        , thumb_width(0)
        , thumb_height(0)
    { }
};

using tgl_download_callback = std::function<void(tgl_download_status, const std::string& file_name, int64_t downloaded_bytes)>;
using tgl_upload_callback = std::function<void(tgl_upload_status, const std::shared_ptr<tgl_message>& message, int64_t uploaded_bytes)>;
using tgl_read_callback = std::function<std::shared_ptr<std::vector<uint8_t>>(uint32_t chunk_size)>;
using tgl_upload_part_done_callback = std::function<void()>;

class tgl_transfer_manager
{
public:
    virtual ~tgl_transfer_manager() { }

    virtual std::string download_directory() const = 0;

    virtual bool file_exists(const tgl_file_location &location) const = 0;

    // Parameter is either secret or access hash depending on file type
    virtual std::string get_file_path(int64_t secret) const = 0;

    virtual void download_by_file_location(int64_t download_id, const tgl_file_location& location,
            int32_t file_size, const tgl_download_callback& callback) = 0;

    virtual void download_document(int64_t download_id, const std::shared_ptr<tgl_document>& document,
            const tgl_download_callback& callback) = 0;

    virtual void cancel_download(int64_t download_id) = 0;

    virtual void upload_document(const tgl_input_peer_t& to_id, int64_t message_id,
            const std::shared_ptr<tgl_upload_document>& document,
            tgl_upload_option option,
            const tgl_upload_callback& callback,
            const tgl_read_callback& read_callback,
            const tgl_upload_part_done_callback& part_done_callback,
            int32_t reply = 0) = 0;

    // Upload self profile photo. The server will cut central square from this photo.
    virtual void upload_profile_photo(const std::string &file_name, int32_t file_size,
            const std::function<void(bool success)>& callback,
            const tgl_read_callback& read_callback,
            const tgl_upload_part_done_callback& done_callback) = 0;

    virtual void upload_chat_photo(const tgl_input_peer_t& chat_id, const std::string &file_name, int32_t file_size,
            const std::function<void(bool success)>& callback,
            const tgl_read_callback& read_callback,
            const tgl_upload_part_done_callback& done_callback) = 0;

    virtual void upload_channel_photo(const tgl_input_peer_t& chat_id, const std::string &file_name, int32_t file_size,
            const std::function<void(bool success)>& callback,
            const tgl_read_callback& read_callback,
            const tgl_upload_part_done_callback& done_callback) = 0;


    virtual void cancel_upload(int64_t message_id) = 0;

    virtual bool is_uploading_file(int64_t message_id) const = 0;

    virtual bool is_downloading_file(int64_t download_id) const = 0;
};

#endif
