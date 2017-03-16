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

#include "tgl/tgl_peer_id.h"
#include "tgl/tgl_transfer_manager.h"

#include <array>
#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

struct tgl_message;

namespace tgl {
namespace impl {

class query_upload_file_part;

class upload_task {
public:
    uintmax_t size;
    uintmax_t uploaded_bytes;
    size_t part_num;
    int64_t id;
    int64_t thumb_id;
    tgl_input_peer_t to_id;
    tgl_document_type doc_type;
    std::string file_name;
    bool as_photo;
    bool animated;
    int32_t avatar;
    int32_t reply;
    std::array<unsigned char, 32> iv;
    std::array<unsigned char, 32> init_iv;
    std::array<unsigned char, 32> key;
    int32_t width;
    int32_t height;
    int32_t duration;
    std::string caption;

    std::vector<uint8_t> thumb;
    int32_t thumb_width;
    int32_t thumb_height;

    int64_t message_id;

    tgl_upload_status status;

    std::unordered_set<size_t> running_parts;
    tgl_upload_callback callback;
    tgl_read_callback read_callback;
    tgl_upload_part_done_callback part_done_callback;

    upload_task();
    ~upload_task();

    bool is_encrypted() const { return to_id.peer_type == tgl_peer_type::enc_chat; }
    bool is_animated() const { return animated; }
    bool is_image() const { return doc_type == tgl_document_type::image; }
    bool is_audio() const { return doc_type == tgl_document_type::audio; }
    bool is_video() const { return doc_type == tgl_document_type::video; }
    bool is_sticker() const { return doc_type == tgl_document_type::sticker; }
    bool is_unknown() const { return doc_type == tgl_document_type::unknown; }

    void set_status(tgl_upload_status status, const std::shared_ptr<tgl_message>& message = nullptr);
    void request_cancel() { m_cancel_requested = true; }
    bool check_cancelled();

private:
    bool m_cancel_requested;
};

}
}
