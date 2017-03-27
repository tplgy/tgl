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

#include "transfer_manager.h"

#include "auto/auto_fetch_ds.h"
#include "auto/auto_free_ds.h"
#include "auto/auto_skip.h"
#include "auto/auto_types.h"
#include "crypto/crypto_aes.h"
#include "crypto/crypto_md5.h"
#include "download_task.h"
#include "message.h"
#include "mtproto_client.h"
#include "mtproto_common.h"
#include "query/query_download_file_part.h"
#include "query/query_messages_send_encrypted_file.h"
#include "query/query_send_messages.h"
#include "query/query_upload_file_part.h"
#include "secret_chat.h"
#include "secret_chat_encryptor.h"
#include "tools.h"
#include "tgl/tgl_mime_type.h"
#include "tgl/tgl_secure_random.h"
#include "tgl/tgl_update_callback.h"
#include "upload_task.h"

#include <boost/filesystem.hpp>
#include <limits>

namespace tgl {
namespace impl {

static constexpr size_t MAX_PART_SIZE = 512 * 1024;

class query_set_photo: public query
{
public:
    query_set_photo(user_agent& ua, const std::function<void(bool)>& callback)
        : query(ua, "set photo", TYPE_TO_PARAM(photos_photo))
        , m_callback(callback)
    { }

    const std::shared_ptr<query_set_photo> shared_from_this()
    {
        return std::static_pointer_cast<query_set_photo>(query::shared_from_this());
    }

    virtual void on_answer(void*) override
    {
        if (m_callback) {
            m_callback(true);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("set photo error: " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false);
        }
        return 0;
    }

private:
    std::function<void(bool)> m_callback;
};

bool transfer_manager::file_exists(const tgl_file_location &location) const
{
    std::string path = get_file_path(location.access_hash());
    return boost::filesystem::exists(path);
}

std::string transfer_manager::get_file_path(int64_t secret) const
{
    std::ostringstream stream;
    stream << download_directory() << "/download_" << secret;
    return stream.str();
}

void transfer_manager::upload_avatar_end(const std::shared_ptr<upload_task>& u, const std::function<void(bool)>& callback)
{
    auto ua = m_user_agent.lock();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        if (callback) {
            callback(false);
        }
        return;
    }

    if (u->avatar > 0) {
        auto q = std::make_shared<query_send_messages>(*ua, callback);
        if (u->to_id.peer_type == tgl_peer_type::channel) {
            q->out_i32(CODE_channels_edit_photo);
            q->out_i32(CODE_input_channel);
        } else {
            q->out_i32(CODE_messages_edit_chat_photo);
        }

        q->out_i32(u->to_id.peer_id);

        if (u->to_id.peer_type == tgl_peer_type::channel) {
            q->out_i64(u->to_id.access_hash);
        }

        q->out_i32(CODE_input_chat_uploaded_photo);
        if (u->size < BIG_FILE_THRESHOLD) {
            q->out_i32(CODE_input_file);
        } else {
            q->out_i32(CODE_input_file_big);
        }
        q->out_i64(u->id);
        q->out_i32(u->part_num);
        q->out_string("");
        if (u->size < BIG_FILE_THRESHOLD) {
            q->out_string("");
        }
        q->out_i32(CODE_input_photo_crop_auto);

        q->execute(ua->active_client());
    } else {
        auto q = std::make_shared<query_set_photo>(*ua, callback);
        q->out_i32(CODE_photos_upload_profile_photo);
        if (u->size < BIG_FILE_THRESHOLD) {
            q->out_i32(CODE_input_file);
        } else {
            q->out_i32(CODE_input_file_big);
        }
        q->out_i64(u->id);
        q->out_i32(u->part_num);
        boost::filesystem::path path(u->file_name);
        q->out_std_string(path.filename().string());
        if (u->size < BIG_FILE_THRESHOLD) {
            q->out_string("");
        }
        q->out_string("profile photo");
        q->out_i32(CODE_input_geo_point_empty);
        q->out_i32(CODE_input_photo_crop_auto);

        q->execute(ua->active_client());
    }
}


void transfer_manager::upload_unencrypted_file_end(const std::shared_ptr<upload_task>& u)
{
    auto ua = m_user_agent.lock();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        u->set_status(tgl_upload_status::failed);
        return;
    }

    auto extra = std::make_shared<messages_send_extra>();
    extra->id = u->message_id;
    auto q = std::make_shared<query_send_messages>(*ua, extra,
            [=](bool success, const std::shared_ptr<tgl_message>& message) {
                u->set_status(success ? tgl_upload_status::succeeded : tgl_upload_status::failed);
            });

    auto m = std::make_shared<message>(u->message_id, ua->our_id(), u->to_id,
            nullptr, nullptr, std::string(), nullptr, nullptr, 0, nullptr);
    q->set_message(m);

    q->out_i32(CODE_messages_send_media);
    q->out_i32((u->reply ? 1 : 0));
    q->out_input_peer(u->to_id);
    if (u->reply) {
        q->out_i32(u->reply);
    }
    if (u->as_photo) {
        q->out_i32(CODE_input_media_uploaded_photo);
    } else {
        if (u->thumb_id != 0) {
            q->out_i32(CODE_input_media_uploaded_thumb_document);
        } else {
            q->out_i32(CODE_input_media_uploaded_document);
        }
    }

    if (u->size < BIG_FILE_THRESHOLD) {
        q->out_i32(CODE_input_file);
    } else {
        q->out_i32(CODE_input_file_big);
    }

    q->out_i64(u->id);
    q->out_i32(u->part_num);
    std::string file_name = boost::filesystem::path(u->file_name).filename().string();
    q->out_std_string(file_name);
    if (u->size < BIG_FILE_THRESHOLD) {
        q->out_string("");
    }

    if (!u->as_photo) {
        if (u->thumb_id != 0) {
            q->out_i32(CODE_input_file);
            q->out_i64(u->thumb_id);
            q->out_i32(1);
            q->out_string("thumb.jpg");
            q->out_string("");
        }

        q->out_std_string(tgl_mime_type_by_filename(u->file_name));

        q->out_i32(CODE_vector);
        if (u->is_image()) {
            if (u->is_animated()) {
                q->out_i32(2);
                q->out_i32(CODE_document_attribute_image_size);
                q->out_i32(u->width);
                q->out_i32(u->height);
                q->out_i32(CODE_document_attribute_animated);
            } else {
                q->out_i32(1);
                q->out_i32(CODE_document_attribute_image_size);
                q->out_i32(u->width);
                q->out_i32(u->height);
            }
        } else if (u->is_audio()) {
            q->out_i32(2);
            q->out_i32(CODE_document_attribute_audio);
            q->out_i32(0);
            q->out_i32(u->duration);
            q->out_i32(CODE_document_attribute_filename);
            q->out_std_string(file_name);
        } else if (u->is_video()) {
            q->out_i32(2);
            q->out_i32(CODE_document_attribute_video);
            q->out_i32(u->duration);
            q->out_i32(u->width);
            q->out_i32(u->height);
            q->out_i32(CODE_document_attribute_filename);
            q->out_std_string(file_name);
        } else if (u->is_sticker()) {
            q->out_i32(1);
            q->out_i32(CODE_document_attribute_sticker);
        } else {
            assert(u->is_unknown());
            q->out_i32(1);
            q->out_i32(CODE_document_attribute_filename);
            q->out_std_string(file_name);
        }

        q->out_std_string(u->caption);
    } else {
        q->out_std_string(u->caption);
    }

    q->out_i64(extra->id);

    q->execute(ua->active_client());
}

void transfer_manager::upload_encrypted_file_end(const std::shared_ptr<upload_task>& u)
{
    auto ua = m_user_agent.lock();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        u->set_status(tgl_upload_status::failed);
        return;
    }

    std::shared_ptr<secret_chat> sc = ua->secret_chat_for_id(u->to_id);
    if (!sc) {
        TGL_ERROR("the secret chat has gone");
        u->set_status(tgl_upload_status::failed);
        return;
    }

    tgl_peer_id_t from_id = ua->our_id();
    int64_t date = tgl_get_system_time();
    auto m = std::make_shared<message>(sc,
            u->message_id,
            from_id,
            &date,
            std::string(),
            nullptr,
            nullptr,
            nullptr);
    m->set_pending(true).set_unread(true);
    auto q = std::make_shared<query_messages_send_encrypted_file>(*ua, sc, u, m,
            [=](bool success, const std::shared_ptr<tgl_message>&) {
                u->set_status(success ? tgl_upload_status::succeeded : tgl_upload_status::failed);
            });

    q->execute(ua->active_client());
}

void transfer_manager::upload_end(const std::shared_ptr<upload_task>& u)
{
    auto it = m_uploads.find(u->message_id);
    if (it == m_uploads.end()) {
        TGL_DEBUG("upload already finished");
        return;
    }

    TGL_DEBUG("uploaded all parts");

    m_uploads.erase(it);

    if (u->status != tgl_upload_status::uploading) {
        return;
    }

    if (u->avatar) {
        upload_avatar_end(u,
                [=](bool success) {
                    u->set_status(success ? tgl_upload_status::succeeded : tgl_upload_status::failed);
                });
        return;
    }
    if (u->is_encrypted()) {
        upload_encrypted_file_end(u);
    } else {
        upload_unencrypted_file_end(u);
    }
    return;
}

void transfer_manager::upload_multiple_parts(const std::shared_ptr<upload_task>&u, size_t count)
{
    for (size_t i = 0; u->part_num * MAX_PART_SIZE < u->size && i < count; ++i) {
        upload_part(u);
    }
}

void transfer_manager::upload_part_finished(const std::shared_ptr<upload_task>& u, size_t part_number, bool success)
{
    u->running_parts.erase(part_number);

    u->uploaded_bytes += MAX_PART_SIZE;
    if (u->uploaded_bytes > u->size) {
        u->uploaded_bytes = u->size;
    }

    if (u->part_done_callback) {
        u->part_done_callback();
    }

    if (!success || u->check_cancelled()) {
        if (!success) {
            u->set_status(tgl_upload_status::failed);
        }
        upload_end(u);
        return;
    }

    if (u->status == tgl_upload_status::waiting || u->status == tgl_upload_status::connecting) {
        u->set_status(tgl_upload_status::uploading);
    }

    if (u->part_num * MAX_PART_SIZE < u->size) {
        upload_part(u);
    } else if (u->running_parts.empty()) {
        upload_end(u);
    }
}

void transfer_manager::upload_part(const std::shared_ptr<upload_task>& u)
{
    auto ua = m_user_agent.lock();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        u->set_status(tgl_upload_status::failed);
        upload_end(u);
        return;
    }

    auto offset = u->part_num * MAX_PART_SIZE;
    u->running_parts.insert(u->part_num);
    auto q = std::make_shared<query_upload_file_part>(*ua, u, std::bind(&transfer_manager::upload_part_finished,
            shared_from_this(), u, u->part_num, std::placeholders::_1));
    if (u->size < BIG_FILE_THRESHOLD) {
        q->out_i32(CODE_upload_save_file_part);
        q->out_i64(u->id);
        q->out_i32(u->part_num++);
    } else {
        q->out_i32(CODE_upload_save_big_file_part);
        q->out_i64(u->id);
        q->out_i32(u->part_num++);
        q->out_i32((u->size + MAX_PART_SIZE - 1) / MAX_PART_SIZE);
    }

    auto sending_buffer = u->read_callback(MAX_PART_SIZE);
    size_t read_size = sending_buffer->size();

    if (read_size == 0) {
        TGL_WARNING("could not send empty file");
        u->set_status(tgl_upload_status::failed);
        upload_end(u);
        return;
    }

    assert(read_size > 0);
    offset += read_size;

    if (u->is_encrypted()) {
        if (read_size & 15) {
            assert(offset == u->size);
            int32_t padding_size = (-read_size) & 15;
            sending_buffer->resize(read_size + padding_size);
            tgl_secure_random(reinterpret_cast<unsigned char*>(sending_buffer->data()) + read_size, padding_size);
            read_size += padding_size;
        }

        TGLC_aes_key aes_key;
        TGLC_aes_set_encrypt_key(u->key.data(), 256, &aes_key);
        TGLC_aes_ige_encrypt(reinterpret_cast<unsigned char*>(sending_buffer->data()),
                reinterpret_cast<unsigned char*>(sending_buffer->data()), read_size, &aes_key, u->iv.data(), 1);
        memset(&aes_key, 0, sizeof(aes_key));
    }
    q->out_string(reinterpret_cast<const char*>(sending_buffer->data()), read_size);

    if (offset != u->size) {
        assert(MAX_PART_SIZE == read_size);
    }
    q->execute(ua->active_client());
}

void transfer_manager::upload_thumb(const std::shared_ptr<upload_task>& u)
{
    auto ua = m_user_agent.lock();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        u->set_status(tgl_upload_status::failed);
        upload_end(u);
        return;
    }

    TGL_DEBUG("upload_thumb " << u->thumb.size() << " bytes @ " << u->thumb_width << "x" << u->thumb_height);

    if (u->thumb.size() > MAX_PART_SIZE) {
        TGL_ERROR("the thumnail size of " << u->thumb.size() << " is larger than the maximum part size of " << MAX_PART_SIZE);
        u->set_status(tgl_upload_status::failed);
        upload_end(u);
        return;
    }

    auto q = std::make_shared<query_upload_file_part>(*ua, u, std::bind(&transfer_manager::upload_part_finished,
            shared_from_this(), u, std::numeric_limits<size_t>::max(), std::placeholders::_1));
    while (u->thumb_id == 0) {
        u->thumb_id = tgl_random<int64_t>();
    }
    q->out_i32(CODE_upload_save_file_part);
    q->out_i64(u->thumb_id);
    q->out_i32(0);
    q->out_string(reinterpret_cast<char*>(u->thumb.data()), u->thumb.size());

    q->execute(ua->active_client());
}


void transfer_manager::upload_document(const tgl_input_peer_t& to_id,
        int64_t message_id, int32_t avatar, int32_t reply, bool as_photo,
        const std::shared_ptr<tgl_upload_document>& document,
        const tgl_upload_callback& callback,
        const tgl_read_callback& read_callback,
        const tgl_upload_part_done_callback& done_callback)
{
    TGL_DEBUG("upload_document " << document->file_name << " with size " << document->file_size
            << " and dimension " << document->width << "x" << document->height);

    auto u = std::make_shared<upload_task>();
    u->callback = callback;
    u->read_callback = read_callback;
    u->part_done_callback = done_callback;

    u->size = document->file_size;

    u->set_status(tgl_upload_status::waiting);

    static constexpr int MAX_PARTS = 3000; // How do we get this number?
    if (((u->size + MAX_PART_SIZE - 1) / MAX_PART_SIZE) > MAX_PARTS) {
        TGL_ERROR("file is too big");
        u->set_status(tgl_upload_status::failed);
        upload_end(u);
        return;
    }

    if (!u->size) {
        TGL_ERROR("can not upload empty file");
        u->set_status(tgl_upload_status::failed);
        upload_end(u);
        return;
    }

    auto ua = m_user_agent.lock();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        u->set_status(tgl_upload_status::failed);
        upload_end(u);
        return;
    }

    while (!u->id) {
        tgl_secure_random(reinterpret_cast<unsigned char*>(&u->id), 8);
    }
    while (!message_id) {
        tgl_secure_random(reinterpret_cast<unsigned char*>(&message_id), 8);
    }
    u->avatar = avatar;
    u->message_id = message_id;
    u->reply = reply;
    u->as_photo = as_photo;
    u->to_id = to_id;
    u->doc_type = document->type;
    u->animated = document->is_animated;
    u->file_name = std::move(document->file_name);
    u->width = document->width;
    u->height = document->height;
    u->duration = document->duration;
    u->caption = std::move(document->caption);

    if (u->is_encrypted()) {
        tgl_secure_random(u->iv.data(), u->iv.size());
        memcpy(u->init_iv.data(), u->iv.data(), u->iv.size());
        tgl_secure_random(u->key.data(), u->key.size());
    }

    auto thumb_size = document->thumb_data.size();
    if (thumb_size) {
        u->thumb = std::move(document->thumb_data);
        u->thumb_width = document->thumb_width;
        u->thumb_height = document->thumb_height;
    }

    m_uploads[message_id] = u;

    if (!u->is_encrypted() && thumb_size > 0) {
        upload_thumb(u);
        upload_multiple_parts(u, ua->active_client()->max_connections() - 1);
    } else {
        upload_multiple_parts(u, ua->active_client()->max_connections());
    }
}

void transfer_manager::upload_photo(const tgl_input_peer_t& chat_id, const std::string& file_name, int32_t file_size,
        const std::function<void(bool success)>& callback,
        const tgl_read_callback& read_callback,
        const tgl_upload_part_done_callback& done_callback)
{
    auto document = std::make_shared<tgl_upload_document>();
    document->type = tgl_document_type::image;
    document->file_name = file_name;
    document->file_size = file_size;
    upload_document(chat_id,
            0 /* message_id */,
            1 /* avatar -1 indicates avatar*/,
            chat_id.peer_id /* reply */,
            true /* as_photo */,
            document,
            [=](tgl_upload_status status, const std::shared_ptr<tgl_message>&, float) {
                if (callback) {
                    callback(status == tgl_upload_status::succeeded);
                }
            },
            read_callback,
            done_callback);
}

void transfer_manager::upload_chat_photo(const tgl_input_peer_t& chat_id, const std::string& file_name, int32_t file_size,
        const std::function<void(bool success)>& callback,
        const tgl_read_callback& read_callback,
        const tgl_upload_part_done_callback& done_callback)
{
    assert(chat_id.peer_type == tgl_peer_type::chat);
    upload_photo(chat_id, file_name, file_size, callback, read_callback, done_callback);
}

void transfer_manager::upload_channel_photo(const tgl_input_peer_t& chat_id, const std::string& file_name, int32_t file_size,
        const std::function<void(bool success)>& callback,
        const tgl_read_callback& read_callback,
        const tgl_upload_part_done_callback& done_callback)
{
    assert(chat_id.peer_type == tgl_peer_type::channel);
    upload_photo(chat_id, file_name, file_size, callback, read_callback, done_callback);
}

void transfer_manager::upload_profile_photo(const std::string& file_name, int32_t file_size,
        const std::function<void(bool success)>& callback,
        const tgl_read_callback& read_callback,
        const tgl_upload_part_done_callback& done_callback)
{
    auto ua = m_user_agent.lock();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        if (callback) {
            callback(false);
        }
        return;
    }

    auto document = std::make_shared<tgl_upload_document>();
    document->type = tgl_document_type::image;
    document->file_name = file_name;
    document->file_size = file_size;
    upload_document(tgl_input_peer_t::from_peer_id(ua->our_id()),
            0 /* message_id */,
            -1 /* avatar */,
            0 /* reply */,
            true /* as_photo */,
            document,
            [=](tgl_upload_status status, const std::shared_ptr<tgl_message>&, float) {
                if (callback) {
                    if (status == tgl_upload_status::succeeded) {
                        callback(true);
                    } else if (status == tgl_upload_status::failed) {
                        callback(false);
                    } else if (status == tgl_upload_status::uploading) {
                        // ignore uploading status
                    }
                }
            },
            read_callback,
            done_callback);
}

void transfer_manager::upload_document(const tgl_input_peer_t& to_id, int64_t message_id,
        const std::shared_ptr<tgl_upload_document>& document,
        tgl_upload_option option,
        const tgl_upload_callback& callback,
        const tgl_read_callback& read_callback,
        const tgl_upload_part_done_callback& done_callback,
        int32_t reply)
{
    TGL_DEBUG("upload_document - file_name: " << document->file_name);

    bool as_photo = false;
    if (option == tgl_upload_option::auto_detect_document_type) {
        std::string mime_type = tgl_mime_type_by_filename(document->file_name);
        TGL_DEBUG("upload_document - detected mime_type: " << mime_type);
        if (!memcmp(mime_type.c_str(), "image/", 6)) {
            document->type = tgl_document_type::image;
            if (!strcmp(mime_type.c_str(), "image/gif")) {
                document->is_animated = true;
            }
        } else if (!memcmp(mime_type.c_str(), "video/", 6)) {
            document->type = tgl_document_type::video;
        } else if (!memcmp(mime_type.c_str(), "audio/", 6)) {
            document->type = tgl_document_type::audio;
        } else {
            document->type = tgl_document_type::unknown;
        }
    } else if (option == tgl_upload_option::as_photo) {
        as_photo = true;
    } else {
        assert(option == tgl_upload_option::as_document);
    }

    upload_document(to_id, message_id, 0 /* avatar */, reply, as_photo, document, callback, read_callback, done_callback);
}

void transfer_manager::download_end(const std::shared_ptr<download_task>& d)
{
    auto it = m_downloads.find(d->id);
    if (it == m_downloads.end()) {
        TGL_DEBUG("download " << d->id << " has finshed");
        return;
    }

    m_downloads.erase(it);

    d->file_stream.reset();

    if (d->status != tgl_download_status::downloading && !d->file_name.empty()) {
        boost::system::error_code ec;
        boost::filesystem::remove(d->file_name, ec);
        if (ec) {
            TGL_WARNING("failed to remove cancelled download: " << d->file_name << ": " << ec.value() << " - " << ec.message());
        }
        d->file_name = std::string();
    } else {
        d->set_status(tgl_download_status::succeeded);
    }
}

void transfer_manager::download_part_finished(const std::shared_ptr<download_task>& d, size_t offset,
        const tl_ds_upload_file* DS_UF)
{
    if (!DS_UF || d->check_cancelled()) {
        if (!DS_UF) {
            d->set_status(tgl_download_status::failed);
        }
        d->running_parts.clear();
        download_end(d);
        return;
    }

    if (!d->file_stream) {
        d->file_stream = std::make_unique<std::ofstream>(d->file_name, std::ios_base::trunc | std::ios_base::out | std::ios_base::binary);
        if (!d->file_stream || !d->file_stream->good()) {
            TGL_ERROR("can not open file [" << d->file_name << "] for writing");
            d->set_status(tgl_download_status::failed);
            d->running_parts.clear();
            download_end(d);
            return;
        }
    }

    if (!DS_UF->bytes || !DS_UF->bytes->data || DS_UF->bytes->len <= 0) {
        TGL_ERROR("the server returned nothing to us");
        d->set_status(tgl_download_status::failed);
        d->running_parts.clear();
        download_end(d);
        return;
    }

    if (!d->iv.empty()) {
        d->running_parts[offset] = download_data(DS_UF->bytes->data, DS_UF->bytes->len, false);
        auto it = d->running_parts.begin();
        for (;it != d->running_parts.end() && d->decryption_offset == it->first && it->second; ++it) {
            char* data = it->second.data();
            size_t length = it->second.length();
            if (length & 15) {
                TGL_ERROR("the encrypted data length is not half byte aligned");
                assert(false);
                d->set_status(tgl_download_status::failed);
                d->running_parts.clear();
                download_end(d);
            }
            TGLC_aes_key aes_key;
            TGLC_aes_set_decrypt_key(d->key.data(), 256, &aes_key);
            TGLC_aes_ige_encrypt(reinterpret_cast<const unsigned char*>(data),
                    reinterpret_cast<unsigned char*>(data), length, &aes_key, d->iv.data(), 0);
            memset(&aes_key, 0, sizeof(aes_key));
            if (length > d->size - it->first) {
                length = d->size - it->first;
            }
            d->file_stream->seekp(it->first);
            d->file_stream->write(data, length);
            d->decryption_offset += length;
        }
        if (it == d->running_parts.begin()) {
            d->running_parts[offset] = download_data(DS_UF->bytes->data, DS_UF->bytes->len, true);
        } else {
            d->running_parts.erase(d->running_parts.begin(), it);
        }
    } else {
        d->file_stream->seekp(offset);
        d->file_stream->write(DS_UF->bytes->data, DS_UF->bytes->len);
        d->running_parts.erase(offset);
    }

    d->downloaded_bytes += DS_UF->bytes->len;

    if (d->status == tgl_download_status::waiting || d->status == tgl_download_status::connecting) {
        d->set_status(tgl_download_status::downloading);
    }

    if (d->offset < d->size) {
        download_part(d);
    } else if (d->running_parts.empty()) {
        download_end(d);
    }
}

void transfer_manager::download_multiple_parts(const std::shared_ptr<download_task>& d, size_t count)
{
    for (size_t i = 0; d->offset < d->size && i < count; ++i) {
        download_part(d);
    }
}

void transfer_manager::download_part(const std::shared_ptr<download_task>& d)
{
    TGL_DEBUG("download_part from offset " << d->offset << "(file size " << d->size << ")");

    auto ua = m_user_agent.lock();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        d->set_status(tgl_download_status::failed);
        d->running_parts.clear();
        download_end(d);
        return;
    }

    if (!d->offset) {
        std::string path = get_file_path(d->location.access_hash());
        if (!d->ext.empty()) {
            path += std::string(".") + d->ext;
        }
        d->file_name = path;
    }

    d->running_parts[d->offset] = download_data();

    auto q = std::make_shared<query_download_file_part>(*ua, d, std::bind(&transfer_manager::download_part_finished,
            shared_from_this(), d, d->offset, std::placeholders::_1));

    q->out_i32(CODE_upload_get_file);
    if (d->location.local_id()) {
        q->out_i32(CODE_input_file_location);
        q->out_i64(d->location.volume());
        q->out_i32(d->location.local_id());
        q->out_i64(d->location.secret());
    } else {
        q->out_i32(d->type);
        q->out_i64(d->location.document_id());
        q->out_i64(d->location.access_hash());
    }
    q->out_i32(d->offset);
    q->out_i32(MAX_PART_SIZE);
    d->offset += MAX_PART_SIZE;

    q->execute(ua->client_at(d->location.dc()));
}

void transfer_manager::download_by_file_location(int64_t download_id,
        const tgl_file_location& file_location, const int32_t file_size,
        const tgl_download_callback& callback)
{
    if (m_downloads.count(download_id)) {
        TGL_ERROR("duplicate download id " << download_id);
        if (callback) {
            callback(tgl_download_status::failed, std::string(), 0);
        }
        return;
    }

    if (!file_location.dc()) {
        TGL_ERROR("bad file location");
        if (callback) {
            callback(tgl_download_status::failed, std::string(), 0);
        }
        return;
    }

    auto ua = m_user_agent.lock();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        if (callback) {
            callback(tgl_download_status::failed, std::string(), 0);
        }
        return;
    }

    TGL_DEBUG("download_file_location - file_size: " << file_size);

    auto d = std::make_shared<download_task>(download_id, file_size, file_location);
    d->callback = callback;
    m_downloads[d->id] = d;
    d->set_status(tgl_download_status::waiting);
    if (file_size <= 0) { // It's likely for avatar which doesn't have a file size
        download_part(d);
    } else {
        download_multiple_parts(d, ua->client_at(d->location.dc())->max_connections());
    }
}

void transfer_manager::download_document(int64_t download_id,
        const std::shared_ptr<tgl_download_document>& document,
        const tgl_download_callback& callback)
{
    if (m_downloads.count(download_id)) {
        TGL_ERROR("duplicate download id " << download_id);
        if (callback) {
            callback(tgl_download_status::failed, std::string(), 0);
        }
        return;
    }

    auto ua = m_user_agent.lock();
    if (!ua) {
        TGL_ERROR("the user agent has gone");
        if (callback) {
            callback(tgl_download_status::failed, std::string(), 0);
        }
        return;
    }

    std::shared_ptr<download_task> d = std::make_shared<download_task>(download_id, document);
    d->callback = callback;

    if (!d->valid) {
        TGL_WARNING("encrypted document key finger print doesn't match");
        d->set_status(tgl_download_status::failed);
        return;
    }

    m_downloads[d->id] = d;
    if (!document->mime_type.empty()) {
        d->ext = tgl_extension_by_mime_type(document->mime_type);
    }
    d->set_status(tgl_download_status::waiting);
    download_multiple_parts(d, ua->client_at(d->location.dc())->max_connections());
}

void transfer_manager::cancel_download(int64_t download_id)
{
    auto it = m_downloads.find(download_id);
    if (it == m_downloads.end()) {
        TGL_DEBUG("can't find download " << download_id);
        return;
    }
    it->second->request_cancel();
    TGL_DEBUG("download " << download_id << " has been cancelled");
}

void transfer_manager::cancel_upload(int64_t message_id)
{
    auto it = m_uploads.find(message_id);
    if (it == m_uploads.end()) {
        TGL_DEBUG("can't find upload " << message_id);
        return;
    }
    it->second->request_cancel();
    TGL_DEBUG("upload " << message_id << " has been cancelled");
}

bool transfer_manager::is_uploading_file(int64_t message_id) const
{
    return m_uploads.count(message_id);
}

bool transfer_manager::is_downloading_file(int64_t download_id) const
{
    return m_downloads.count(download_id);
}

}
}
