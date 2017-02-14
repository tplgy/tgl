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

#include "auto/auto-fetch-ds.h"
#include "auto/auto-free-ds.h"
#include "auto/auto-skip.h"
#include "crypto/tgl_crypto_aes.h"
#include "crypto/tgl_crypto_md5.h"
#include "download_task.h"
#include "mtproto_client.h"
#include "mtproto-common.h"
#include "query/queries.h"
#include "query/query_messages_send_encrypted_file.h"
#include "query/query_upload_file_part.h"
#include "secret_chat_encryptor.h"
#include "tools.h"
#include "tgl/tgl_mime_type.h"
#include "tgl/tgl_secret_chat.h"
#include "tgl/tgl_secure_random.h"
#include "tgl/tgl_update_callback.h"
#include "tgl_secret_chat_private.h"
#include "upload_task.h"

#include <fcntl.h>
#include <boost/filesystem.hpp>
#include <fstream>
#include <limits>

static constexpr size_t MAX_PART_SIZE = 512 * 1024;

class query_set_photo: public query
{
public:
    explicit query_set_photo(const std::function<void(bool)>& callback)
        : query("set photo", TYPE_TO_PARAM(photos_photo))
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

class query_download: public query
{
public:
    query_download(transfer_manager* manager,
            const std::shared_ptr<download_task>& download,
            const tgl_download_callback& callback)
        : query("download", TYPE_TO_PARAM(upload_file))
        , m_manager(manager)
        , m_download(download)
        , m_callback(callback)
    { }

    const std::shared_ptr<query_download> shared_from_this()
    {
        return std::static_pointer_cast<query_download>(query::shared_from_this());
    }

    virtual void on_answer(void* answer) override
    {
        m_manager->download_on_answer(shared_from_this(), answer);
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        return m_manager->download_on_error(shared_from_this(), error_code, error_string);
    }

    virtual double timeout_interval() const override
    {
        return 20.0;
    }

    virtual void on_connection_status_changed(tgl_connection_status status) override
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

        set_download_status(download_status);
    }

    virtual void will_send() override
    {
        if (download_finished()) {
            return;
        }
        set_download_status(tgl_download_status::downloading);
    }

    virtual bool is_file_transfer() const override { return true; }

    const tgl_download_callback& callback() const
    {
        return m_callback;
    }

    const std::shared_ptr<download_task>& get_download() const
    {
        return m_download;
    }

    void set_download_status(tgl_download_status status)
    {
        m_download->status = status;
        if (m_callback) {
            std::string file_name = (status == tgl_download_status::succeeded || status == tgl_download_status::cancelled) ? m_download->file_name : std::string();
            m_callback(status, file_name, m_download->offset);
        }
    }

private:
    bool download_finished() const
    {
        return m_download->status == tgl_download_status::succeeded
                || m_download->status == tgl_download_status::failed
                || m_download->status == tgl_download_status::cancelled;
    }

private:
    transfer_manager* m_manager;
    std::shared_ptr<download_task> m_download;
    tgl_download_callback m_callback;
};

std::shared_ptr<tgl_transfer_manager> tgl_transfer_manager::create_default_impl(const std::string& download_dir)
{
    return std::make_shared<transfer_manager>(download_dir);
}

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
    if (u->avatar > 0) {
        auto q = std::make_shared<query_send_msgs>(callback);
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

        q->execute(tgl_state::instance()->active_client());
    } else {
        auto q = std::make_shared<query_set_photo>(callback);
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

        q->execute(tgl_state::instance()->active_client());
    }
}


void transfer_manager::upload_unencrypted_file_end(const std::shared_ptr<upload_task>& u)
{
    auto extra = std::make_shared<messages_send_extra>();
    extra->id = u->message_id;
    auto q = std::make_shared<query_send_msgs>(extra,
            [=](bool success, const std::shared_ptr<tgl_message>& message) {
                u->set_status(success ? tgl_upload_status::succeeded : tgl_upload_status::failed);
            });

    auto message = std::make_shared<tgl_message>();
    message->permanent_id = u->message_id;
    message->to_id = u->to_id;
    message->from_id = tgl_state::instance()->our_id();
    q->set_message(message);

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
            q->out_i32(u->duration);
            q->out_std_string("");
            q->out_std_string("");
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

    q->execute(tgl_state::instance()->active_client());
}

void transfer_manager::upload_encrypted_file_end(const std::shared_ptr<upload_task>& u)
{
    std::shared_ptr<tgl_secret_chat> secret_chat = tgl_state::instance()->secret_chat_for_id(u->to_id);
    assert(secret_chat);

    tgl_peer_id_t from_id = tgl_state::instance()->our_id();
    int64_t date = tgl_get_system_time();
    std::shared_ptr<tgl_message> message = std::make_shared<tgl_message>(secret_chat,
            u->message_id,
            from_id,
            &date,
            std::string(),
            nullptr,
            nullptr,
            nullptr);
    message->set_pending(true).set_unread(true);
    auto q = std::make_shared<query_messages_send_encrypted_file>(secret_chat, u, message,
            [=](bool success, const std::shared_ptr<tgl_message>& message) {
                u->set_status(success ? tgl_upload_status::succeeded : tgl_upload_status::failed);
            });

    q->execute(tgl_state::instance()->active_client());
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
    for (size_t i = 0; !u->at_EOF && i < count; ++i) {
        upload_part(u);
    }
}

void transfer_manager::upload_part_finished(const std::shared_ptr<upload_task>&u, size_t part_number, bool success)
{
    if (u->part_done_callback) {
        u->part_done_callback();
    }

    u->running_parts.erase(part_number);

    if (!success || u->check_cancelled()) {
        upload_end(u);
        return;
    }

    if (u->at_EOF && u->running_parts.empty()) {
        upload_end(u);
        return;
    }

    if (!u->at_EOF) {
        upload_part(u);
    }
}

void transfer_manager::upload_part(const std::shared_ptr<upload_task>& u)
{
    assert(!u->at_EOF);

    auto offset = u->part_num * u->part_size;
    u->running_parts.insert(u->part_num);
    auto q = std::make_shared<query_upload_file_part>(u, std::bind(&transfer_manager::upload_part_finished,
            shared_from_this(), u, u->part_num, std::placeholders::_1));
    if (u->size < BIG_FILE_THRESHOLD) {
        q->out_i32(CODE_upload_save_file_part);
        q->out_i64(u->id);
        q->out_i32(u->part_num++);
    } else {
        q->out_i32(CODE_upload_save_big_file_part);
        q->out_i64(u->id);
        q->out_i32(u->part_num++);
        q->out_i32((u->size + u->part_size - 1) / u->part_size);
    }

    auto sending_buffer = u->read_callback(u->part_size);
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
            tgl_secure_random(reinterpret_cast<unsigned char*>(sending_buffer->data()) + read_size, (-read_size) & 15);
            read_size = (read_size + 15) & ~15;
        }

        TGLC_aes_key aes_key;
        TGLC_aes_set_encrypt_key(u->key.data(), 256, &aes_key);
        TGLC_aes_ige_encrypt(reinterpret_cast<unsigned char*>(sending_buffer->data()),
                reinterpret_cast<unsigned char*>(sending_buffer->data()), read_size, &aes_key, u->iv.data(), 1);
        memset(&aes_key, 0, sizeof(aes_key));
    }
    q->out_string(reinterpret_cast<char*>(sending_buffer->data()), read_size);

    if (offset == u->size) {
        u->at_EOF = true;
    } else {
        assert(u->part_size == read_size);
    }
    q->execute(tgl_state::instance()->active_client());
}

void transfer_manager::upload_thumb(const std::shared_ptr<upload_task>& u)
{
    TGL_NOTICE("upload_thumb " << u->thumb.size() << " bytes @ " << u->thumb_width << "x" << u->thumb_height);

    if (u->thumb.size() > MAX_PART_SIZE) {
        TGL_ERROR("the thumnail size of " << u->thumb.size() << " is larger than the maximum part size of " << MAX_PART_SIZE);
        u->set_status(tgl_upload_status::failed);
        upload_end(u);
        return;
    }

    auto q = std::make_shared<query_upload_file_part>(u, std::bind(&transfer_manager::upload_part_finished,
            shared_from_this(), u, std::numeric_limits<size_t>::max(), std::placeholders::_1));
    while (u->thumb_id == 0) {
        u->thumb_id = tgl_random<int64_t>();
    }
    q->out_i32(CODE_upload_save_file_part);
    q->out_i64(u->thumb_id);
    q->out_i32(0);
    q->out_string(reinterpret_cast<char*>(u->thumb.data()), u->thumb.size());

    q->execute(tgl_state::instance()->active_client());
}


void transfer_manager::upload_document(const tgl_input_peer_t& to_id,
        int64_t message_id, int32_t avatar, int32_t reply, bool as_photo,
        const std::shared_ptr<tgl_upload_document>& document,
        const tgl_upload_callback& callback,
        const tgl_read_callback& read_callback,
        const tgl_upload_part_done_callback& done_callback)
{
    TGL_NOTICE("upload_document " << document->file_name << " with size " << document->file_size
            << " and dimension " << document->width << "x" << document->height);

    auto u = std::make_shared<upload_task>();
    u->callback = callback;
    u->read_callback = read_callback;
    u->part_done_callback = done_callback;

    u->size = document->file_size;
    u->part_size = MAX_PART_SIZE;

    u->set_status(tgl_upload_status::waiting);

    static constexpr int MAX_PARTS = 3000; // How do we get this number?
    if (((u->size + u->part_size - 1) / u->part_size) > MAX_PARTS) {
        TGL_ERROR("file is too big");
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
        upload_multiple_parts(u, tgl_state::instance()->active_client()->max_connections() - 1);
    } else {
        upload_multiple_parts(u, tgl_state::instance()->active_client()->max_connections());
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
    auto document = std::make_shared<tgl_upload_document>();
    document->type = tgl_document_type::image;
    document->file_name = file_name;
    document->file_size = file_size;
    upload_document(tgl_input_peer_t::from_peer_id(tgl_state::instance()->our_id()),
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

void transfer_manager::end_download(const std::shared_ptr<download_task>& d,
        const tgl_download_callback& callback)
{
    m_downloads.erase(d->id);

    if (d->fd >= 0) {
        close(d->fd);
    }

    if (d->status == tgl_download_status::cancelled) {
        boost::system::error_code ec;
        boost::filesystem::remove(d->file_name, ec);
        if (ec) {
            TGL_WARNING("failed to remove cancelled download: " << d->file_name << ": " << ec.value() << " - " << ec.message());
        }
        d->file_name = std::string();
    } else {
        d->status = tgl_download_status::succeeded;
    }

    if (callback) {
        callback(d->status, d->file_name, d->size);
    }
}

int transfer_manager::download_on_answer(const std::shared_ptr<query_download>& q, void* DD)
{
    tl_ds_upload_file* DS_UF = static_cast<tl_ds_upload_file*>(DD);

    const std::shared_ptr<download_task>& d = q->get_download();
    if (d->fd == -1) {
        d->fd = open(d->file_name.c_str(), O_CREAT | O_WRONLY, 0640);
        if (d->fd < 0) {
            TGL_ERROR("can not open file [" << d->file_name << "] for writing: " << errno << " - " << strerror(errno));
            q->set_download_status(tgl_download_status::failed);
            return 0;
        }
    }

    int32_t len = DS_UF->bytes->len;

    if (!d->iv.empty()) {
        assert(!(len & 15));
        void* ptr = DS_UF->bytes->data;

        TGLC_aes_key aes_key;
        TGLC_aes_set_decrypt_key(d->key.data(), 256, &aes_key);
        TGLC_aes_ige_encrypt(static_cast<unsigned char*>(ptr), static_cast<unsigned char*>(ptr), len, &aes_key, d->iv.data(), 0);
        memset(&aes_key, 0, sizeof(aes_key));
        if (len > d->size - d->offset) {
            len = d->size - d->offset;
        }
        auto result = write(d->fd, ptr, len);
        TGL_ASSERT_UNUSED(result, result == len);
    } else {
        auto result = write(d->fd, DS_UF->bytes->data, len);
        TGL_ASSERT_UNUSED(result, result == len);
    }

    d->offset += len;
    if (d->offset < d->size) {
        auto status = q->get_download()->status;
        if (status == tgl_download_status::waiting || status == tgl_download_status::connecting) {
            q->set_download_status(tgl_download_status::downloading);
        }
        download_next_part(d, q->callback());
        return 0;
    } else {
        end_download(d, q->callback());
        return 0;
    }
}

int transfer_manager::download_on_error(const std::shared_ptr<query_download>& q, int error_code, const std::string &error)
{
    TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << std::string(error));

    const std::shared_ptr<download_task>& d = q->get_download();
    if (d->fd >= 0) {
        close(d->fd);
    }

    boost::system::error_code ec;
    boost::filesystem::remove(d->file_name, ec);
    d->file_name = std::string();

    q->set_download_status(tgl_download_status::failed);

    return 0;
}

void transfer_manager::download_next_part(const std::shared_ptr<download_task>& d,
        const tgl_download_callback& callback)
{
    if (d->status == tgl_download_status::cancelled) {
        end_download(d, callback);
        return;
    }

    TGL_DEBUG("download_next_part (file size " << d->size << ")");
    if (!d->offset) {
        std::string path = get_file_path(d->location.access_hash());

        if (!d->ext.empty()) {
            path += std::string(".") + d->ext;
        }

        d->file_name = path;
        if (boost::filesystem::exists(path)) {
            boost::system::error_code ec;
            d->offset = boost::filesystem::file_size(path, ec);
            if (!ec && d->offset >= d->size) {
                TGL_NOTICE("file [" << path << "] already downloaded");
                end_download(d, callback);
                return;
            }
        }

    }
    auto q = std::make_shared<query_download>(this, d, callback);
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

    q->execute(tgl_state::instance()->client_at(d->location.dc()));
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

    auto d = std::make_shared<download_task>(download_id, file_size, file_location);
    m_downloads[d->id] = d;

    if (callback) {
        callback(d->status, std::string(), 0);
    }

    TGL_DEBUG("download_file_location - file_size: " << file_size);
    download_next_part(d, callback);
}

void transfer_manager::download_document(const std::shared_ptr<download_task>& d,
        const std::string& mime_type,
        const tgl_download_callback& callback)
{
    if (!mime_type.empty()) {
        d->ext = tgl_extension_by_mime_type(mime_type);
    }
    download_next_part(d, callback);
}

void transfer_manager::download_document(int64_t download_id,
        const std::shared_ptr<tgl_document>& document,
        const tgl_download_callback& callback)
{
    if (m_downloads.count(download_id)) {
        TGL_ERROR("duplicate download id " << download_id);
        if (callback) {
            callback(tgl_download_status::failed, std::string(), 0);
        }
        return;
    }

    std::shared_ptr<download_task> d = std::make_shared<download_task>(download_id, document);

    if (!d->valid) {
        TGL_WARNING("encrypted document key finger print doesn't match");
        d->status = tgl_download_status::failed;
        if (callback) {
            callback(d->status, std::string(), 0);
        }
        return;
    }

    m_downloads[d->id] = d;

    if (callback) {
        callback(d->status, std::string(), 0);
    }

    download_document(d, document->mime_type, callback);
}

void transfer_manager::cancel_download(int64_t download_id)
{
    auto it = m_downloads.find(download_id);
    if (it == m_downloads.end()) {
        TGL_DEBUG("can't find download " << download_id);
        return;
    }
    it->second->status = tgl_download_status::cancelled;
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
