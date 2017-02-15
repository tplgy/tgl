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

    Copyright Vitaly Valtman 2013-2015
    Copyright Topology LP 2016-2017
*/

#include "query_messages_send_encrypted_file.h"

#include "auto/constants.h"
#include "auto/auto-fetch-ds.h"
#include "auto/auto-free-ds.h"
#include "auto/auto-skip.h"
#include "crypto/tgl_crypto_md5.h"
#include "secret_chat_encryptor.h"
#include "tgl/tgl_mime_type.h"
#include "transfer_manager.h"
#include "upload_task.h"

#include <boost/filesystem.hpp>
#include <cstring>

query_messages_send_encrypted_file::query_messages_send_encrypted_file(
        const std::shared_ptr<tgl_secret_chat>& secret_chat,
        const std::shared_ptr<tgl_unconfirmed_secret_message>& unconfirmed_message,
        const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback) throw(std::runtime_error)
    : query_messages_send_encrypted_base("send encrypted file message (reassembled)", secret_chat, nullptr, callback, true)
{
    const auto& blobs = unconfirmed_message->blobs();
    if (unconfirmed_message->constructor_code() != CODE_messages_send_encrypted_file
            || blobs.size() != 2) {
        throw std::runtime_error("invalid message blobs for query_messages_send_encrypted_file");
    }

    const std::string& layer_blob = blobs[0];
    const std::string& input_file_info_blob = blobs[1];
    if ((layer_blob.size() % 4) || (input_file_info_blob.size() % 4)) {
        throw std::runtime_error("message blobs for query_messages_send_encrypted_file don't align in 4 bytes boundary");
    }

    out_i32(CODE_messages_send_encrypted_file);
    out_i32(CODE_input_encrypted_chat);
    out_i32(m_secret_chat->id().peer_id);
    out_i64(m_secret_chat->id().access_hash);
    out_i64(unconfirmed_message->message_id());
    secret_chat_encryptor encryptor(m_secret_chat, serializer());
    encryptor.start();
    out_i32s(reinterpret_cast<const int32_t*>(layer_blob.data()), layer_blob.size() / 4);
    encryptor.end();
    out_i32s(reinterpret_cast<const int32_t*>(input_file_info_blob.data()), input_file_info_blob.size() / 4);

    construct_message(unconfirmed_message->message_id(), unconfirmed_message->date(), layer_blob);
}

void query_messages_send_encrypted_file::set_message_media(const tl_ds_decrypted_message_media* DS_DMM)
{
    m_message->set_decrypted_message_media(DS_DMM);

    if (m_message->media->type() == tgl_message_media_type::document_encr) {
        if (auto encr_document = std::static_pointer_cast<tgl_message_media_document_encr>(m_message->media)->encr_document) {
            const auto& u = m_upload;
            if (u->is_image() || u->as_photo) {
                encr_document->type = tgl_document_type::image;
                if (u->is_animated()) {
                    encr_document->is_animated = true;
                } else {
                    encr_document->is_animated = false;
                }
            } else if (u->is_video()) {
                encr_document->type = tgl_document_type::video;
            } else if (u->is_audio()) {
                encr_document->type = tgl_document_type::audio;
            } else if (u->is_sticker()) {
                encr_document->type = tgl_document_type::sticker;
            } else {
                encr_document->type = tgl_document_type::unknown;
            }
        }
    }
}

void query_messages_send_encrypted_file::assemble()
{
    const auto& u = m_upload;

    out_i32(CODE_messages_send_encrypted_file);
    out_i32(CODE_input_encrypted_chat);
    out_i32(u->to_id.peer_id);
    out_i64(m_secret_chat->id().access_hash);
    out_i64(m_message->permanent_id);
    secret_chat_encryptor encryptor(m_secret_chat, serializer());
    encryptor.start();
    size_t capture_start = begin_unconfirmed_message(CODE_messages_send_encrypted_file);
    out_i32(CODE_decrypted_message_layer);
    out_random(15 + 4 * (tgl_random<int>() % 3));
    out_i32(TGL_ENCRYPTED_LAYER);
    out_i32(m_secret_chat->private_facet()->raw_in_seq_no());
    out_i32(m_secret_chat->private_facet()->raw_out_seq_no());
    out_i32(CODE_decrypted_message);
    out_i64(m_message->permanent_id);
    out_i32(m_secret_chat->ttl());
    out_string("");

    size_t start = serializer()->i32_size();

    if (u->as_photo) {
        out_i32(CODE_decrypted_message_media_photo);
    } else if (u->is_video()) {
        out_i32(CODE_decrypted_message_media_video);
    } else if (u->is_audio()) {
        out_i32(CODE_decrypted_message_media_audio);
    } else {
        out_i32(CODE_decrypted_message_media_document);
    }
    if (u->as_photo || !u->is_audio()) {
        TGL_DEBUG("secret chat thumb data " << u->thumb.size() << " bytes @ " << u->thumb_width << "x" << u->thumb_height);
        out_string(reinterpret_cast<char*>(u->thumb.data()), u->thumb.size());
        out_i32(u->thumb_width);
        out_i32(u->thumb_height);
    }

    if (u->as_photo) {
        out_i32(u->width);
        out_i32(u->height);
    } else if (u->is_video()) {
        out_i32(u->duration);
        out_std_string(tgl_mime_type_by_filename(u->file_name));
        out_i32(u->width);
        out_i32(u->height);
    } else if (u->is_audio()) {
        out_i32(u->duration);
        out_std_string(tgl_mime_type_by_filename(u->file_name));
    } else { // document
        boost::filesystem::path path(u->file_name);
        out_std_string(path.filename().string());
        out_std_string(tgl_mime_type_by_filename(u->file_name));
    }

    out_i32(u->size);
    out_string(reinterpret_cast<const char*>(u->key.data()), u->key.size());
    out_string(reinterpret_cast<const char*>(u->init_iv.data()), u->init_iv.size());

    tgl_in_buffer in = { serializer()->i32_data() + start, serializer()->i32_data() + serializer()->i32_size() };

    struct paramed_type decrypted_message_media = TYPE_TO_PARAM(decrypted_message_media);
    auto result = skip_type_any(&in, &decrypted_message_media);
    TGL_ASSERT_UNUSED(result, result >= 0);
    assert(in.ptr == in.end);

    in = { serializer()->i32_data() + start, serializer()->i32_data() + serializer()->i32_size() };
    tl_ds_decrypted_message_media* DS_DMM = fetch_ds_type_decrypted_message_media(&in, &decrypted_message_media);
    set_message_media(DS_DMM);
    assert(in.ptr == in.end);

    append_blob_to_unconfirmed_message(capture_start);

    encryptor.end();

    capture_start = serializer()->char_size();
    if (u->size < BIG_FILE_THRESHOLD) {
        out_i32(CODE_input_encrypted_file_uploaded);
    } else {
        out_i32(CODE_input_encrypted_file_big_uploaded);
    }
    out_i64(u->id);
    out_i32(u->part_num);
    if (u->size < BIG_FILE_THRESHOLD) {
        out_string("");
    }

    unsigned char md5[16];
    unsigned char str[64];
    memcpy(str, u->key.data(), 32);
    memcpy(str + 32, u->init_iv.data(), 32);
    TGLC_md5(str, 64, md5);
    out_i32((*(int *)md5) ^ (*(int *)(md5 + 4)));

    append_blob_to_unconfirmed_message(capture_start);

    free_ds_type_decrypted_message_media(DS_DMM, &decrypted_message_media);
}
