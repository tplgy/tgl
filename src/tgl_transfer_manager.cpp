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

#include "auto/auto-fetch-ds.h"
#include "auto/auto-free-ds.h"
#include "auto/auto-skip.h"
#include "crypto/tgl_crypto_aes.h"
#include "crypto/tgl_crypto_md5.h"
#include "mtproto_client.h"
#include "mtproto-common.h"
#include "queries.h"
#include "queries-encrypted.h"
#include "query_messages_send_encrypted_file.h"
#include "secret_chat_encryptor.h"
#include "tools.h"
#include "tgl/tgl_mime_type.h"
#include "tgl/tgl_transfer_manager.h"
#include "tgl/tgl_secret_chat.h"
#include "tgl/tgl_secure_random.h"
#include "tgl/tgl_update_callback.h"
#include "tgl_secret_chat_private.h"

#include <fcntl.h>
#include <boost/filesystem.hpp>
#include <fstream>

static constexpr size_t BIG_FILE_THRESHOLD = 10 * 1024 * 1024;
static constexpr size_t MAX_PART_SIZE = 512 * 1024;

struct tgl_upload {
    uintmax_t size;
    uintmax_t offset;
    size_t part_num;
    size_t part_size;
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
    bool at_EOF;

    tgl_upload()
        : size(0)
        , offset(0)
        , part_num(0)
        , part_size(0)
        , id(0)
        , thumb_id(0)
        , to_id()
        , doc_type(tgl_document_type::unknown)
        , as_photo(false)
        , animated(false)
        , avatar(0)
        , reply(0)
        , width(0)
        , height(0)
        , duration(0)
        , thumb_width(0)
        , thumb_height(0)
        , message_id(0)
        , status(tgl_upload_status::waiting)
        , at_EOF(false)
    { }

    ~tgl_upload()
    {
        // For security reasion.
        memset(iv.data(), 0, iv.size());
        memset(init_iv.data(), 0, init_iv.size());
        memset(key.data(), 0, key.size());
    }

    bool is_encrypted() const { return to_id.peer_type == tgl_peer_type::enc_chat; }
    bool is_animated() const { return animated; }
    bool is_image() const { return doc_type == tgl_document_type::image; }
    bool is_audio() const { return doc_type == tgl_document_type::audio; }
    bool is_video() const { return doc_type == tgl_document_type::video; }
    bool is_sticker() const { return doc_type == tgl_document_type::sticker; }
    bool is_unknown() const { return doc_type == tgl_document_type::unknown; }
};

struct tgl_download {
    tgl_download(int32_t size, const tgl_file_location& location)
        : id(next_id())
        , offset(0)
        , size(size)
        , type(0)
        , fd(-1)
        , location(location)
        , status(tgl_download_status::waiting)
        , iv()
        , key()
        , valid(true)
    {
    }

    tgl_download(const std::shared_ptr<tgl_document>& document)
        : id(next_id())
        , offset(0)
        , size(document->size)
        , type(0)
        , fd(-1)
        , location()
        , status(tgl_download_status::waiting)
        , iv()
        , key()
        , valid(true)
    {
        location.set_dc(document->dc_id);
        location.set_local_id(0);
        location.set_secret(document->access_hash);
        location.set_volume(document->id);
        init_from_document(document);
    }

    ~tgl_download()
    {
        memset(iv.data(), 0, iv.size());
        memset(key.data(), 0, key.size());
    }

    int32_t id;
    int32_t offset;
    int32_t size;
    int32_t type;
    int fd;
    tgl_file_location location;
    std::string file_name;
    std::string ext;
    tgl_download_status status;
    //encrypted documents
    std::vector<unsigned char> iv;
    std::vector<unsigned char> key;
    bool valid;
    // ---

    static int32_t next_id()
    {
        static int32_t next = 0;
        return ++next;
    }

private:
    void init_from_document(const std::shared_ptr<tgl_document>& document)
    {
        if (document->is_encrypted()) {
            type = CODE_input_encrypted_file_location;
            auto encr_document = std::static_pointer_cast<tgl_encr_document>(document);
            iv = std::move(encr_document->iv);
            key = std::move(encr_document->key);
            unsigned char md5[16];
            unsigned char str[64];
            memcpy(str, key.data(), 32);
            memcpy(str + 32, iv.data(), 32);
            TGLC_md5(str, 64, md5);
            if (encr_document->key_fingerprint != ((*(int *)md5) ^ (*(int *)(md5 + 4)))) {
                valid = false;
                return;
            }
            return;
        }

        switch (document->type) {
        case tgl_document_type::audio:
            type = CODE_input_audio_file_location;
            break;
        case tgl_document_type::video:
            type = CODE_input_video_file_location;
            break;
        default:
            type = CODE_input_document_file_location;
            break;
        }
    }
};

class query_upload_part: public query
{
public:
    query_upload_part(tgl_transfer_manager* download_manager,
            const std::shared_ptr<tgl_upload>& u,
            const tgl_upload_callback& callback,
            const tgl_read_callback& read_callback,
            const tgl_upload_part_done_callback& done_callback)
        : query("upload part", TYPE_TO_PARAM(bool))
        , m_download_manager(download_manager)
        , m_upload(u)
        , m_callback(callback)
        , m_read_callback(read_callback)
        , m_done_callback(done_callback)
    { }

    ~query_upload_part()
    {
        if (m_done_callback) {
            m_done_callback();
        }
    }

    const std::shared_ptr<query_upload_part> shared_from_this()
    {
        return std::static_pointer_cast<query_upload_part>(query::shared_from_this());
    }

    virtual void on_answer(void* answer) override
    {
        m_download_manager->upload_part_on_answer(shared_from_this(), answer);
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        set_upload_status(tgl_upload_status::failed);
        return 0;
    }

    virtual double timeout_interval() const override
    {
        // We upload part of size 512KB. If the user has 512Kbps upload
        // speed that would be at least 8 seconds. Considering not everyone gets
        // full claimed speed we double the time needed for the speeed of 512Kbps.
        // It turns out the time is 16 seconds. And then we add a little bit of
        // offset of 4 seconds.
        return 20;
    }

    virtual void connection_status_changed(tgl_connection_status status) override
    {
        if (upload_finished()) {
            return;
        }

        tgl_upload_status upload_status = m_upload->status;

        switch (status) {
        case tgl_connection_status::connecting:
            upload_status = tgl_upload_status::connecting;
            break;
        case tgl_connection_status::disconnected:
        case tgl_connection_status::connected:
            upload_status = tgl_upload_status::waiting;
            break;
        }

        set_upload_status(upload_status);
    }

    virtual void will_send() override
    {
        if (upload_finished()) {
            return;
        }
        set_upload_status(tgl_upload_status::uploading);
    }

    void set_upload_status(tgl_upload_status status, const std::shared_ptr<tgl_message>& message = nullptr)
    {
        m_upload->status = status;
        if (m_callback) {
            m_callback(status, message, m_upload->offset);
        }
    }


    const tgl_upload_callback& callback() const
    {
        return m_callback;
    }

    const std::shared_ptr<tgl_upload>& get_upload() const
    {
        return m_upload;
    }

    const tgl_read_callback& read_callback() const
    {
        return m_read_callback;
    }

    const tgl_upload_part_done_callback& done_callback() const
    {
        return m_done_callback;
    }

private:
    bool upload_finished() const
    {
        return m_upload->status == tgl_upload_status::succeeded
                || m_upload->status == tgl_upload_status::failed
                || m_upload->status == tgl_upload_status::cancelled;
    }

private:
    tgl_transfer_manager* m_download_manager;
    std::shared_ptr<tgl_upload> m_upload;
    tgl_upload_callback m_callback;
    tgl_read_callback m_read_callback;
    tgl_upload_part_done_callback m_done_callback;
};

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
    query_download(tgl_transfer_manager* download_manager,
            const std::shared_ptr<tgl_download>& download,
            const tgl_download_callback& callback)
        : query("download", TYPE_TO_PARAM(upload_file))
        , m_download_manager(download_manager)
        , m_download(download)
        , m_callback(callback)
    { }

    const std::shared_ptr<query_download> shared_from_this()
    {
        return std::static_pointer_cast<query_download>(query::shared_from_this());
    }

    virtual void on_answer(void* answer) override
    {
        m_download_manager->download_on_answer(shared_from_this(), answer);
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        return m_download_manager->download_on_error(shared_from_this(), error_code, error_string);
    }

    virtual double timeout_interval() const override
    {
        return 20.0;
    }

    virtual void connection_status_changed(tgl_connection_status status) override
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

    const tgl_download_callback& callback() const
    {
        return m_callback;
    }

    const std::shared_ptr<tgl_download>& get_download() const
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
    tgl_transfer_manager* m_download_manager;
    std::shared_ptr<tgl_download> m_download;
    tgl_download_callback m_callback;
};

tgl_transfer_manager::tgl_transfer_manager(std::string download_directory)
    : m_download_directory(download_directory)
{
}

bool tgl_transfer_manager::file_exists(const tgl_file_location &location)
{
    std::string path = get_file_path(location.access_hash());
    return boost::filesystem::exists(path);
}

std::string tgl_transfer_manager::get_file_path(int64_t secret)
{
    std::ostringstream stream;
    stream << download_directory() << "/download_" << secret;
    return stream.str();
}

int tgl_transfer_manager::upload_part_on_answer(const std::shared_ptr<query_upload_part>& q, void*)
{
    const auto& u = q->get_upload();
    u->offset = u->part_num * u->part_size;
    if (u->offset > u->size) {
        u->offset = u->size;
    }

    if (u->status == tgl_upload_status::waiting || u->status == tgl_upload_status::connecting) {
        q->set_upload_status(tgl_upload_status::uploading);
    }

    upload_part(u, q->callback(), q->read_callback(), q->done_callback());
    return 0;
}

void tgl_transfer_manager::upload_avatar_end(const std::shared_ptr<tgl_upload>& u, const std::function<void(bool)>& callback)
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


void tgl_transfer_manager::upload_unencrypted_file_end(const std::shared_ptr<tgl_upload>& u,
        const tgl_upload_callback& callback)
{
    auto extra = std::make_shared<messages_send_extra>();
    extra->id = u->message_id;
    auto q = std::make_shared<query_send_msgs>(extra,
            [=](bool success, const std::shared_ptr<tgl_message>& message) {
                u->status = success ? tgl_upload_status::succeeded : tgl_upload_status::failed;
                callback(u->status, message, u->size);
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

void tgl_transfer_manager::upload_encrypted_file_end(const std::shared_ptr<tgl_upload>& u,
        const tgl_upload_callback& callback)
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
                u->status = success ? tgl_upload_status::succeeded : tgl_upload_status::failed;
                callback(u->status, message, u->size);
            });

    q->execute(tgl_state::instance()->active_client());
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

void tgl_transfer_manager::upload_end(const std::shared_ptr<tgl_upload>& u,
        const tgl_upload_callback& callback)
{
    TGL_NOTICE("upload_end");

    m_uploads.erase(u->message_id);

    if (u->status == tgl_upload_status::cancelled) {
        if (callback) {
            callback(u->status, nullptr, 0);
        }
        return;
    }

    if (u->avatar) {
        upload_avatar_end(u,
                [=](bool success) {
                    u->status = success ? tgl_upload_status::succeeded : tgl_upload_status::failed;
                    if(callback) {
                        callback(u->status, nullptr, u->size);
                    }
                });
        return;
    }
    if (u->is_encrypted()) {
        TGL_NOTICE("upload_end - upload_encrypted_file_end");
        upload_encrypted_file_end(u, callback);
    } else {
        TGL_NOTICE("upload_end - upload_unencrypted_file_end");
        upload_unencrypted_file_end(u, callback);
    }
    return;
}

void tgl_transfer_manager::upload_part(const std::shared_ptr<tgl_upload>& u,
        const tgl_upload_callback& callback,
        const tgl_read_callback& read_callback,
        const tgl_upload_part_done_callback& done_callback)
{
    if (u->status == tgl_upload_status::cancelled) {
        done_callback();
        upload_end(u, callback);
        return;
    }

    if (!u->at_EOF) {
        auto q = std::make_shared<query_upload_part>(this, u, callback, read_callback, done_callback);
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

        auto sending_buffer = read_callback(u->part_size);
        size_t read_size = sending_buffer->size();

        if (read_size == 0) {
            TGL_WARNING("could not send empty file");
            u->status = tgl_upload_status::failed;
            if (callback) {
                callback(u->status, nullptr, 0);
            }
            return;
        }

        assert(read_size > 0);
        uintmax_t offset = u->offset + read_size;

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
    } else {
        upload_end(u, callback);
    }
}

void tgl_transfer_manager::upload_thumb(const std::shared_ptr<tgl_upload>& u,
        const tgl_upload_callback& callback,
        const tgl_read_callback& read_callback,
        const tgl_upload_part_done_callback& done_callback)
{
    TGL_NOTICE("upload_thumb " << u->thumb.size() << " bytes @ " << u->thumb_width << "x" << u->thumb_height);

    if (u->status == tgl_upload_status::cancelled) {
        done_callback();
        upload_end(u, callback);
        return;
    }

    if (u->thumb.size() > MAX_PART_SIZE) {
        TGL_ERROR("the thumnail size of " << u->thumb.size() << " is larger than the maximum part size of " << MAX_PART_SIZE);
        u->status = tgl_upload_status::failed;
        if (callback) {
            callback(u->status, nullptr, 0);
        }
    }

    auto q = std::make_shared<query_upload_part>(this, u, callback, read_callback, done_callback);
    while (u->thumb_id == 0) {
        u->thumb_id = tgl_random<int64_t>();
    }
    q->out_i32(CODE_upload_save_file_part);
    q->out_i64(u->thumb_id);
    q->out_i32(0);
    q->out_string(reinterpret_cast<char*>(u->thumb.data()), u->thumb.size());

    q->execute(tgl_state::instance()->active_client());
}


void tgl_transfer_manager::upload_document(const tgl_input_peer_t& to_id,
        int64_t message_id, int32_t avatar, int32_t reply, bool as_photo,
        const std::shared_ptr<tgl_upload_document>& document,
        const tgl_upload_callback& callback,
        const tgl_read_callback& read_callback,
        const tgl_upload_part_done_callback& done_callback)
{
    TGL_NOTICE("upload_document " << document->file_name << " with size " << document->file_size
            << " and dimension " << document->width << "x" << document->height);

    auto u = std::make_shared<tgl_upload>();
    u->size = document->file_size;
    u->part_size = MAX_PART_SIZE;

    if (callback) {
        callback(u->status, nullptr, 0);
    }

    static constexpr int MAX_PARTS = 3000; // How do we get this number?
    if (((u->size + u->part_size - 1) / u->part_size) > MAX_PARTS) {
        TGL_ERROR("file is too big");
        u->status = tgl_upload_status::failed;
        if (callback) {
            callback(u->status, nullptr, 0);
        }
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
        upload_thumb(u, callback, read_callback, done_callback);
    } else {
        upload_part(u, callback, read_callback, done_callback);
    }
}

void tgl_transfer_manager::upload_photo(const tgl_input_peer_t& chat_id, const std::string& file_name, int32_t file_size,
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

void tgl_transfer_manager::upload_chat_photo(const tgl_input_peer_t& chat_id, const std::string& file_name, int32_t file_size,
        const std::function<void(bool success)>& callback,
        const tgl_read_callback& read_callback,
        const tgl_upload_part_done_callback& done_callback)
{
    assert(chat_id.peer_type == tgl_peer_type::chat);
    upload_photo(chat_id, file_name, file_size, callback, read_callback, done_callback);
}

void tgl_transfer_manager::upload_channel_photo(const tgl_input_peer_t& chat_id, const std::string& file_name, int32_t file_size,
        const std::function<void(bool success)>& callback,
        const tgl_read_callback& read_callback,
        const tgl_upload_part_done_callback& done_callback)
{
    assert(chat_id.peer_type == tgl_peer_type::channel);
    upload_photo(chat_id, file_name, file_size, callback, read_callback, done_callback);
}

void tgl_transfer_manager::upload_profile_photo(const std::string& file_name, int32_t file_size,
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

void tgl_transfer_manager::upload_document(const tgl_input_peer_t& to_id, int64_t message_id,
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

void tgl_transfer_manager::end_download(const std::shared_ptr<tgl_download>& d,
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

int tgl_transfer_manager::download_on_answer(const std::shared_ptr<query_download>& q, void* DD)
{
    tl_ds_upload_file* DS_UF = static_cast<tl_ds_upload_file*>(DD);

    const std::shared_ptr<tgl_download>& d = q->get_download();
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

int tgl_transfer_manager::download_on_error(const std::shared_ptr<query_download>& q, int error_code, const std::string &error)
{
    TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << std::string(error));

    const std::shared_ptr<tgl_download>& d = q->get_download();
    if (d->fd >= 0) {
        close(d->fd);
    }

    boost::system::error_code ec;
    boost::filesystem::remove(d->file_name, ec);
    d->file_name = std::string();

    q->set_download_status(tgl_download_status::failed);

    return 0;
}

void tgl_transfer_manager::begin_download(const std::shared_ptr<tgl_download>& new_download)
{
    m_downloads[new_download->id] = new_download;
}

void tgl_transfer_manager::download_next_part(const std::shared_ptr<tgl_download>& d,
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

int32_t tgl_transfer_manager::download_by_file_location(const tgl_file_location& file_location, const int32_t file_size,
        const tgl_download_callback& callback)
{
    if (!file_location.dc()) {
        TGL_ERROR("bad file location");
        if (callback) {
            callback(tgl_download_status::failed, std::string(), 0);
        }
        return 0;
    }

    auto d = std::make_shared<tgl_download>(file_size, file_location);
    if (callback) {
        callback(d->status, std::string(), 0);
    }

    TGL_DEBUG("download_file_location - file_size: " << file_size);
    download_next_part(d, callback);
    return d->id;
}

int32_t tgl_transfer_manager::download_document(const std::shared_ptr<tgl_download>& d,
        const std::string& mime_type,
        const tgl_download_callback& callback)
{
    if (!mime_type.empty()) {
        d->ext = tgl_extension_by_mime_type(mime_type);
    }
    begin_download(d);
    download_next_part(d, callback);
    return d->id;
}

int32_t tgl_transfer_manager::download_document(const std::shared_ptr<tgl_document>& document,
        const tgl_download_callback& callback)
{
    std::shared_ptr<tgl_download> d = std::make_shared<tgl_download>(document);
    if (callback) {
        callback(d->status, std::string(), 0);
    }

    if (!d->valid) {
        TGL_WARNING("encrypted document key finger print doesn't match");
        if (callback) {
            callback(tgl_download_status::failed, std::string(), 0);
        }
        return 0;
    }

    return download_document(d, document->mime_type, callback);
}

void tgl_transfer_manager::cancel_download(int32_t download_id)
{
    auto it = m_downloads.find(download_id);
    if (it == m_downloads.end()) {
        TGL_DEBUG("can't find download " << download_id);
        return;
    }
    it->second->status = tgl_download_status::cancelled;
    TGL_DEBUG("download " << download_id << " has been cancelled");
}

void tgl_transfer_manager::cancel_upload(int64_t message_id)
{
    auto it = m_uploads.find(message_id);
    if (it == m_uploads.end()) {
        TGL_DEBUG("can't find upload " << message_id);
        return;
    }
    it->second->status = tgl_upload_status::cancelled;
    TGL_DEBUG("upload " << message_id << " has been cancelled");
}

bool tgl_transfer_manager::is_uploading_file(int64_t message_id) const
{
    return m_uploads.count(message_id);
}
