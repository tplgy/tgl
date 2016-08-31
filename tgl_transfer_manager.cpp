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
#include "tgl_transfer_manager.h"
#include "queries.h"
#include "tg-mime-types.h"
#include "tgl-layout.h"
#include "crypto/aes.h"
#include "crypto/md5.h"
#include "mtproto-common.h"
#include "tools.h"
#include "types/tgl_secret_chat.h"
#include "types/tgl_update_callback.h"
#include "queries-encrypted.h"

#include <fcntl.h>
#include <boost/filesystem.hpp>
#include <fstream>

static constexpr size_t BIG_FILE_THRESHOLD = 16 * 1024 * 1024;
static constexpr size_t MAX_PART_SIZE = 512 * 1024;

struct tgl_upload {
    uintmax_t size;
    uintmax_t offset;
    size_t part_num;
    size_t part_size;
    int64_t id;
    int64_t thumb_id;
    tgl_input_peer_t to_id;
    int32_t flags;
    std::string file_name;
    bool encr;
    bool cancelled;
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

    bool at_EOF;

    tgl_upload()
        : size(0)
        , offset(0)
        , part_num(0)
        , part_size(0)
        , id(0)
        , thumb_id(0)
        , to_id()
        , flags(0)
        , encr(false)
        , cancelled(false)
        , avatar(0)
        , reply(0)
        , width(0)
        , height(0)
        , duration(0)
        , thumb_width(0)
        , thumb_height(0)
        , at_EOF(false)
    { }

    ~tgl_upload()
    {
        // For security reasion.
        memset(iv.data(), 0, iv.size());
        memset(init_iv.data(), 0, init_iv.size());
        memset(key.data(), 0, key.size());
    }
};

struct tgl_download {
    tgl_download(int32_t size, const tgl_file_location& location)
        : id(next_id())
        , offset(0)
        , size(size)
        , type(0)
        , fd(-1)
        , cancelled(false)
        , location(location)
        , iv()
        , key()
    {
    }

    tgl_download(int32_t type, const std::shared_ptr<tgl_document>& document)
        : id(next_id())
        , offset(0)
        , size(document->size)
        , type(type)
        , fd(-1)
        , cancelled(false)
        , iv()
        , key()
    {
        location.set_dc(document->dc_id);
        location.set_local_id(0);
        location.set_secret(document->access_hash);
        location.set_volume(document->id);
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
    bool cancelled;
    tgl_file_location location;
    std::string file_name;
    std::string ext;
    //encrypted documents
    std::vector<unsigned char> iv;
    std::vector<unsigned char> key;
    // ---

    static int32_t next_id()
    {
        static int32_t next = 0;
        return ++next;
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
        TGL_DEBUG("offset=" << m_upload->offset << " size=" << m_upload->size);

        if (m_callback) {
            float progress = static_cast<float>(m_upload->offset) / m_upload->size;
            m_callback(tgl_upload_status::uploading, nullptr, progress);
        }

        m_download_manager->upload_part_on_answer(shared_from_this(), answer);
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << error_string);
        if (m_callback) {
            m_callback(tgl_upload_status::failed, nullptr, 0);
        }
        return 0;
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

    const tgl_download_callback& callback() const
    {
        return m_callback;
    }

    const std::shared_ptr<tgl_download>& get_download() const
    {
        return m_download;
    }

private:
    tgl_transfer_manager* m_download_manager;
    std::shared_ptr<tgl_download> m_download;
    tgl_download_callback m_callback;
};

class query_upload_encrypted_file: public query
{
public:
    query_upload_encrypted_file(
            const std::shared_ptr<tgl_secret_chat>& secret_chat,
            const std::shared_ptr<tgl_message>& message,
            const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback)
        : query("upload encrypted file", TYPE_TO_PARAM(messages_sent_encrypted_message))
        , m_secret_chat(secret_chat)
        , m_message(message)
        , m_callback(callback)
    { }

    void set_message(const std::shared_ptr<tgl_message>& message)
    {
        m_message = message;
    }

    virtual void on_answer(void* D) override
    {
        tl_ds_messages_sent_encrypted_message* DS_MSEM = static_cast<tl_ds_messages_sent_encrypted_message*>(D);

        m_message->flags = m_message->flags & (~TGLMF_PENDING);
        if (DS_MSEM->date) {
            m_message->date = *DS_MSEM->date;
        }
        if(DS_MSEM->file) {
            tglf_fetch_encrypted_message_file(m_message->media, DS_MSEM->file);
        }
        tgl_state::instance()->callback()->new_messages({m_message});

        if (m_callback) {
            m_callback(true, m_message);
        }

        tgl_state::instance()->callback()->message_sent(m_message, m_message->permanent_id, m_secret_chat->out_seq_no);
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        if (m_secret_chat && m_secret_chat->state != tgl_secret_chat_state::deleted && error_code == 400 && error_string == "ENCRYPTION_DECLINED") {
            tgl_secret_chat_deleted(m_secret_chat);
        }

        if (m_callback) {
            m_callback(false, m_message);
        }

        if (m_message) {
            m_message->flags &= (~TGLMF_PENDING);
            m_message->flags |= (TGLMF_SEND_FAILED);
            tgl_state::instance()->callback()->new_messages({m_message});
        }
        return 0;
    }

private:
    std::shared_ptr<tgl_secret_chat> m_secret_chat;
    std::shared_ptr<tgl_message> m_message;
    std::function<void(bool, const std::shared_ptr<tgl_message>&)> m_callback;
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
    upload_part(q->get_upload(), q->callback(), q->read_callback(), q->done_callback());
    return 0;
}

void tgl_transfer_manager::upload_avatar_end(const std::shared_ptr<tgl_upload>& u, const std::function<void(bool)>& callback)
{
    if (u->avatar > 0) {
        auto q = std::make_shared<query_send_msgs>(callback);
        q->out_i32(CODE_messages_edit_chat_photo);
        q->out_i32(u->avatar);
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

        q->execute(tgl_state::instance()->working_dc());
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

        q->execute(tgl_state::instance()->working_dc());
    }
}


void tgl_transfer_manager::upload_unencrypted_file_end(const std::shared_ptr<tgl_upload>& u,
        const tgl_upload_callback& callback)
{
    auto extra = std::make_shared<messages_send_extra>();
    extra->id = u->message_id;
    auto q = std::make_shared<query_send_msgs>(extra,
            [=](bool success, const std::shared_ptr<tgl_message>& message) {
                callback(success ? tgl_upload_status::succeeded : tgl_upload_status::failed, message, 1);
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
    if (u->flags & TGL_SEND_MSG_FLAG_DOCUMENT_PHOTO) {
        q->out_i32(CODE_input_media_uploaded_photo);
    } else {
        if (u->thumb_id > 0) {
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

    if (!(u->flags & TGL_SEND_MSG_FLAG_DOCUMENT_PHOTO)) {

        if (u->thumb_id > 0) {
            q->out_i32(CODE_input_file);
            q->out_i64(u->thumb_id);
            q->out_i32(1);
            q->out_string("thumb.jpg");
            q->out_string("");
        }

        q->out_string(tg_mime_by_filename(u->file_name.c_str()));

        q->out_i32(CODE_vector);
        if (u->flags & TGLDF_IMAGE) {
            if (u->flags & TGLDF_ANIMATED) {
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
        } else if (u->flags & TGLDF_AUDIO) {
            q->out_i32(2);
            q->out_i32(CODE_document_attribute_audio);
            q->out_i32(u->duration);
            q->out_std_string("");
            q->out_std_string("");
            q->out_i32(CODE_document_attribute_filename);
            q->out_std_string(file_name);
        } else if (u->flags & TGLDF_VIDEO) {
            q->out_i32(2);
            q->out_i32(CODE_document_attribute_video);
            q->out_i32(u->duration);
            q->out_i32(u->width);
            q->out_i32(u->height);
            q->out_i32(CODE_document_attribute_filename);
            q->out_std_string(file_name);
        } else if (u->flags & TGLDF_STICKER) {
            q->out_i32(1);
            q->out_i32(CODE_document_attribute_sticker);
        } else {
            q->out_i32(1);
            q->out_i32(CODE_document_attribute_filename);
            q->out_std_string(file_name);
        }

        q->out_std_string(u->caption);
    } else {
        q->out_std_string(u->caption);
    }

    q->out_i64(extra->id);

    q->execute(tgl_state::instance()->working_dc());
}

void tgl_transfer_manager::upload_encrypted_file_end(const std::shared_ptr<tgl_upload>& u,
        const tgl_upload_callback& callback)
{
    std::shared_ptr<tgl_secret_chat> secret_chat = tgl_state::instance()->secret_chat_for_id(u->to_id);
    assert(secret_chat);
    auto q = std::make_shared<query_upload_encrypted_file>(secret_chat, nullptr,
            [=](bool success, const std::shared_ptr<tgl_message>& message) {
                callback(success ? tgl_upload_status::succeeded : tgl_upload_status::failed, message, 1);
            });
    secret_chat_encryptor encryptor(secret_chat, q->serializer());
    q->out_i32(CODE_messages_send_encrypted_file);
    q->out_i32(CODE_input_encrypted_chat);
    q->out_i32(u->to_id.peer_id);
    q->out_i64(secret_chat->access_hash);
    int64_t r;
    tglt_secure_random(reinterpret_cast<unsigned char*>(&r), 8);
    q->out_i64(r);
    encryptor.start();
    q->out_i32(CODE_decrypted_message_layer);
    q->out_random(15 + 4 * (tgl_random<int>() % 3));
    q->out_i32(TGL_ENCRYPTED_LAYER);
    q->out_i32(2 * secret_chat->in_seq_no + (secret_chat->admin_id != tgl_state::instance()->our_id().peer_id));
    q->out_i32(2 * secret_chat->out_seq_no + (secret_chat->admin_id == tgl_state::instance()->our_id().peer_id));
    q->out_i32(CODE_decrypted_message);
    q->out_i64(r);
    q->out_i32(secret_chat->ttl);
    q->out_string("");

    size_t start = q->serializer()->i32_size();

    if (u->flags & TGL_SEND_MSG_FLAG_DOCUMENT_PHOTO) {
       q->out_i32(CODE_decrypted_message_media_photo);
    } else if ((u->flags & TGLDF_VIDEO)) {
       q->out_i32(CODE_decrypted_message_media_video);
    } else if ((u->flags & TGLDF_AUDIO)) {
       q->out_i32(CODE_decrypted_message_media_audio);
    } else {
       q->out_i32(CODE_decrypted_message_media_document);
    }
    if ((u->flags & TGL_SEND_MSG_FLAG_DOCUMENT_PHOTO) || !(u->flags & TGLDF_AUDIO)) {
        q->out_string(reinterpret_cast<char*>(u->thumb.data()), u->thumb.size());
        q->out_i32(u->thumb_width);
        q->out_i32(u->thumb_height);
    }

    if (u->flags & TGL_SEND_MSG_FLAG_DOCUMENT_PHOTO) {
        q->out_i32(u->width);
        q->out_i32(u->height);
    } else if (u->flags & TGLDF_VIDEO) {
        q->out_i32(u->duration);
        q->out_string(tg_mime_by_filename(u->file_name.c_str()));
        q->out_i32(u->width);
        q->out_i32(u->height);
    } else if (u->flags & TGLDF_AUDIO) {
        q->out_i32(u->duration);
        q->out_string(tg_mime_by_filename(u->file_name.c_str()));
    } else { // document
        boost::filesystem::path path(u->file_name);
        q->out_std_string(path.filename().string());
        q->out_string(tg_mime_by_filename(u->file_name.c_str()));
    }

    q->out_i32(u->size);
    q->out_string(reinterpret_cast<const char*>(u->key.data()), u->key.size());
    q->out_string(reinterpret_cast<const char*>(u->init_iv.data()), u->init_iv.size());

    tgl_in_buffer in = { q->serializer()->mutable_i32_data() + start, q->serializer()->mutable_i32_data() + q->serializer()->i32_size() };

    struct paramed_type decrypted_message_media = TYPE_TO_PARAM(decrypted_message_media);
    auto result = skip_type_any(&in, &decrypted_message_media);
    TGL_ASSERT_UNUSED(result, result >= 0);
    assert(in.ptr == in.end);

    in = { q->serializer()->mutable_i32_data() + start, q->serializer()->mutable_i32_data() + q->serializer()->i32_size() };
    tl_ds_decrypted_message_media* DS_DMM = fetch_ds_type_decrypted_message_media(&in, &decrypted_message_media);
    assert(in.ptr == in.end);

    encryptor.end();

    if (u->size < BIG_FILE_THRESHOLD) {
        q->out_i32(CODE_input_encrypted_file_uploaded);
    } else {
        q->out_i32(CODE_input_encrypted_file_big_uploaded);
    }
    q->out_i64(u->id);
    q->out_i32(u->part_num);
    if (u->size < BIG_FILE_THRESHOLD) {
        q->out_string("");
    }

    unsigned char md5[16];
    unsigned char str[64];
    memcpy(str, u->key.data(), 32);
    memcpy(str + 32, u->init_iv.data(), 32);
    TGLC_md5(str, 64, md5);
    q->out_i32((*(int *)md5) ^ (*(int *)(md5 + 4)));

    tgl_peer_id_t from_id = tgl_state::instance()->our_id();

    int64_t date = tgl_get_system_time();
    std::shared_ptr<tgl_message> message = tglm_create_encr_message(secret_chat,
        u->message_id,
        from_id,
        u->to_id,
        &date,
        std::string(),
        DS_DMM,
        NULL,
        NULL,
        TGLMF_OUT | TGLMF_UNREAD | TGLMF_ENCRYPTED | TGLMF_CREATE | TGLMF_CREATED);
    free_ds_type_decrypted_message_media(DS_DMM, &decrypted_message_media);

    if (message->media->type() == tgl_message_media_type::document_encr) {
        if (auto encr_document = std::static_pointer_cast<tgl_message_media_document_encr>(message->media)->encr_document) {
            if (u->flags & TGL_SEND_MSG_FLAG_DOCUMENT_PHOTO) {
                encr_document->flags |= TGLDF_IMAGE;
            }
            if (u->flags & TGLDF_VIDEO) {
                encr_document->flags |= TGLDF_VIDEO;
            }
            if (u->flags & TGLDF_AUDIO) {
                encr_document->flags |= TGLDF_AUDIO;
            }
        }
    }

    q->set_message(message);
    q->execute(tgl_state::instance()->working_dc());
}

void tgl_transfer_manager::upload_end(const std::shared_ptr<tgl_upload>& u,
        const tgl_upload_callback& callback)
{
    TGL_NOTICE("upload_end");

    m_uploads.erase(u->message_id);

    if (u->cancelled) {
        if (callback) {
            callback(tgl_upload_status::cancelled, nullptr, 1);
        }
        return;
    }

    if (u->avatar) {
        upload_avatar_end(u,
                [=](bool success) {
                    if(callback) {
                        callback(success ? tgl_upload_status::succeeded : tgl_upload_status::failed, nullptr, 0);
                    }
                });
        return;
    }
    if (!u->encr) {
        TGL_NOTICE("upload_end - upload_unencrypted_file_end");
        upload_unencrypted_file_end(u, callback);
        return;
    }
    TGL_NOTICE("upload_end - upload_encrypted_file_end");
    upload_encrypted_file_end(u, callback);
    return;
}

void tgl_transfer_manager::upload_part(const std::shared_ptr<tgl_upload>& u,
        const tgl_upload_callback& callback,
        const tgl_read_callback& read_callback,
        const tgl_upload_part_done_callback& done_callback)
{
    if (u->cancelled) {
        done_callback();
        upload_end(u, callback);
        return;
    }

    if (!u->at_EOF) {
        u->offset = u->part_num * u->part_size;
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
            if (callback) {
                callback(tgl_upload_status::failed, nullptr, 0);
            }
            return;
        }

        assert(read_size > 0);
        u->offset += read_size;

        if (u->encr) {
            if (read_size & 15) {
                assert(u->offset == u->size);
                tglt_secure_random(reinterpret_cast<unsigned char*>(sending_buffer->data()) + read_size, (-read_size) & 15);
                read_size = (read_size + 15) & ~15;
            }

            TGLC_aes_key aes_key;
            TGLC_aes_set_encrypt_key(u->key.data(), 256, &aes_key);
            TGLC_aes_ige_encrypt(reinterpret_cast<unsigned char*>(sending_buffer->data()),
                    reinterpret_cast<unsigned char*>(sending_buffer->data()), read_size, &aes_key, u->iv.data(), 1);
            memset(&aes_key, 0, sizeof(aes_key));
        }
        q->out_string(reinterpret_cast<char*>(sending_buffer->data()), read_size);

        if (u->offset == u->size) {
            u->at_EOF = true;
        } else {
            assert(u->part_size == read_size);
        }
        q->execute(tgl_state::instance()->working_dc());
    } else {
        upload_end(u, callback);
    }
}

void tgl_transfer_manager::upload_thumb(const std::shared_ptr<tgl_upload>& u,
        const tgl_upload_callback& callback,
        const tgl_read_callback& read_callback,
        const tgl_upload_part_done_callback& done_callback)
{
    TGL_NOTICE("upload_thumb");

    if (u->cancelled) {
        done_callback();
        upload_end(u, callback);
        return;
    }

    if (u->thumb.size() > MAX_PART_SIZE) {
        TGL_ERROR("the thumnail size of " << u->thumb.size() << " is larger than the maximum part size of " << MAX_PART_SIZE);
        if (callback) {
            callback(tgl_upload_status::failed, nullptr, 0);
        }
    }

    auto q = std::make_shared<query_upload_part>(this, u, callback, read_callback, done_callback);
    u->thumb_id = tgl_random<int64_t>();
    q->out_i32(CODE_upload_save_file_part);
    q->out_i64(u->thumb_id);
    q->out_i32(0);
    q->out_string(reinterpret_cast<char*>(u->thumb.data()), u->thumb.size());

    q->execute(tgl_state::instance()->working_dc());
}


void tgl_transfer_manager::upload_document(const tgl_input_peer_t& to_id,
        int64_t message_id, const std::string &file_name, int32_t file_size,
        int32_t avatar, int32_t width, int32_t height, int32_t duration,
        const std::string& caption, uint64_t flags,
        const std::vector<uint8_t>& thumb_data, int32_t thumb_width, int32_t thumb_height,
        const tgl_upload_callback& callback,
        const tgl_read_callback& read_callback,
        const tgl_upload_part_done_callback& done_callback)
{
    TGL_NOTICE("upload_document " << file_name << " with size " << file_size << " and dimension " << width << " X " << height);

    auto u = std::make_shared<tgl_upload>();
    u->size = file_size;
    u->avatar = avatar;
    u->message_id = message_id;
    u->reply = flags >> 32;
    u->part_size = MAX_PART_SIZE;
    u->flags = flags;

    static constexpr int MAX_PARTS = 3000; // How do we get this number?
    if (((file_size + u->part_size - 1) / u->part_size) > MAX_PARTS) {
        TGL_ERROR("file is too big");
        if (callback) {
            callback(tgl_upload_status::failed, nullptr, 0);
        }
        return;
    }

    tglt_secure_random(reinterpret_cast<unsigned char*>(&u->id), 8);
    u->to_id = to_id;
    u->flags = flags;
    u->file_name = file_name;
    u->width = width;
    u->height = height;
    u->duration = duration;
    u->caption = caption;

    if (u->to_id.peer_type == tgl_peer_type::enc_chat) {
        u->encr = true;
        tglt_secure_random(u->iv.data(), u->iv.size());
        memcpy(u->init_iv.data(), u->iv.data(), u->iv.size());
        tglt_secure_random(u->key.data(), u->key.size());
    }

    auto thumb_size = thumb_data.size();
    if (thumb_size) {
        u->thumb = thumb_data;
        u->thumb_width = thumb_width;
        u->thumb_height = thumb_height;
    }

    m_uploads[message_id] = u;

    if (!u->encr && u->flags != -1 && thumb_size > 0) {
        upload_thumb(u, callback, read_callback, done_callback);
    } else {
        upload_part(u, callback, read_callback, done_callback);
    }
}

void tgl_transfer_manager::upload_chat_photo(const tgl_input_peer_t& chat_id, const std::string& file_name, int32_t file_size,
        const std::function<void(bool success)>& callback,
        const tgl_read_callback& read_callback,
        const tgl_upload_part_done_callback& done_callback)
{
    assert(chat_id.peer_type == tgl_peer_type::chat);
    upload_document(chat_id, 0, file_name, 0, chat_id.peer_id,
            0, 0, 0, std::string(), TGL_SEND_MSG_FLAG_DOCUMENT_PHOTO, std::vector<uint8_t>(), 0 , 0,
            [=](tgl_upload_status status, const std::shared_ptr<tgl_message>&, float) {
                if (callback) {
                    callback(status == tgl_upload_status::succeeded);
                }
            }, read_callback, done_callback);
}

void tgl_transfer_manager::upload_profile_photo(const std::string& file_name, int32_t file_size,
        const std::function<void(bool success)>& callback,
        const tgl_read_callback& read_callback,
        const tgl_upload_part_done_callback& done_callback)
{
    upload_document(tgl_input_peer_t::from_peer_id(tgl_state::instance()->our_id()), 0, file_name, file_size, -1,
            0, 0, 0, std::string(), TGL_SEND_MSG_FLAG_DOCUMENT_PHOTO, std::vector<uint8_t>(), 0, 0,
            [=](tgl_upload_status status, const std::shared_ptr<tgl_message>&, float) {
                if (callback) {
                    callback(status == tgl_upload_status::succeeded);
                }
            }, read_callback, done_callback);
}

void tgl_transfer_manager::upload_document(const tgl_input_peer_t& to_id, int64_t message_id,
        const std::string& file_name, int32_t file_size, int32_t width, int32_t height, int32_t duration, const std::string& caption,
        const std::vector<uint8_t>& thumb_data, int32_t thumb_width, int32_t thumb_height, uint64_t flags,
        const tgl_upload_callback& callback,
        const tgl_read_callback& read_callback,
        const tgl_upload_part_done_callback& done_callback)
{
    TGL_DEBUG("upload_document - file_name: " + file_name);
    if (flags & TGL_SEND_MSG_FLAG_DOCUMENT_AUTO) {
        const char* mime_type = tg_mime_by_filename(file_name.c_str());
        TGL_DEBUG("upload_document - detected mime_type: " + std::string(mime_type));
        if (strcmp(mime_type, "image/gif") == 0) {
            flags |= TGL_SEND_MSG_FLAG_DOCUMENT_ANIMATED;
        } else if (!memcmp(mime_type, "image/", 6)) {
            flags |= TGL_SEND_MSG_FLAG_DOCUMENT_PHOTO;
        } else if (!memcmp(mime_type, "video/", 6)) {
            flags |= TGLDF_VIDEO;
        } else if (!memcmp(mime_type, "audio/", 6)) {
            flags |= TGLDF_AUDIO;
        }
    }

    upload_document(to_id, message_id, file_name, file_size, 0,
            width, height, duration, caption, flags, thumb_data, thumb_width, thumb_height, callback, read_callback, done_callback);
}

void tgl_transfer_manager::end_download(const std::shared_ptr<tgl_download>& d,
        const tgl_download_callback& callback)
{
    m_downloads.erase(d->id);

    if (d->fd >= 0) {
        close(d->fd);
    }

    if (d->cancelled) {
        boost::system::error_code ec;
        boost::filesystem::remove(d->file_name, ec);
        if (ec) {
            TGL_WARNING("failed to remove cancelled download: " << d->file_name << ": " << ec.value() << " - " << ec.message());
        }
        d->file_name = std::string();
    }

    if (callback) {
        callback(d->cancelled ? tgl_download_status::cancelled : tgl_download_status::succeeded, d->file_name, 1);
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
            if (q->callback()) {
                (q->callback())(tgl_download_status::failed, std::string(), 0);
            }

            return 0;
        }
    }

    int len = DS_UF->bytes->len;

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
        float progress = static_cast<float>(d->offset)/d->size;
        (q->callback())(tgl_download_status::downloading, std::string(), progress);
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

    if (q->callback()) {
        (q->callback())(tgl_download_status::failed, d->file_name, 0);
    }

    return 0;
}

void tgl_transfer_manager::begin_download(const std::shared_ptr<tgl_download>& new_download)
{
    m_downloads[new_download->id] = new_download;
}

void tgl_transfer_manager::download_next_part(const std::shared_ptr<tgl_download>& d,
        const tgl_download_callback& callback)
{
    if (d->cancelled) {
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
                TGL_NOTICE("Already downloaded");
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
        if (!d->iv.empty()) {
            q->out_i32(CODE_input_encrypted_file_location);
        } else {
            q->out_i32(d->type);
        }
        q->out_i64(d->location.document_id());
        q->out_i64(d->location.access_hash());
    }
    q->out_i32(d->offset);
    q->out_i32(MAX_PART_SIZE);

    q->execute(tgl_state::instance()->dc_at(d->location.dc()));
}

int32_t tgl_transfer_manager::download_by_photo_size(const std::shared_ptr<tgl_photo_size>& photo_size,
        const tgl_download_callback& callback)
{
    assert(photo_size);
    if (!photo_size->loc.dc()) {
        TGL_WARNING("bad video thumb");
        if (callback) {
            callback(tgl_download_status::failed, std::string(), 0);
        }
        return 0;
    }

    auto d = std::make_shared<tgl_download>(photo_size->size, photo_size->loc);
    download_next_part(d, callback);
    return d->id;
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
    TGL_DEBUG("download_file_location - file_size: " << file_size);
    download_next_part(d, callback);
    return d->id;
}

int32_t tgl_transfer_manager::download_photo(const std::shared_ptr<tgl_photo>& photo,
        const tgl_download_callback& callback)
{
    if (!photo->sizes.size()) {
        TGL_ERROR("bad photo (no photo sizes");
        if (callback) {
            callback(tgl_download_status::failed, std::string(), 0);
        }
        return 0;
    }
    size_t max_i = 0;
    int max = photo->sizes[0]->w + photo->sizes[0]->h;
    for (size_t i = 1; i < photo->sizes.size(); ++i) {
        int current = photo->sizes[i]->w + photo->sizes[i]->h;
        if (current > max) {
            max = current;
            max_i = i;
        }
    }
    return download_by_photo_size(photo->sizes[max_i], callback);
}

int32_t tgl_transfer_manager::download_document_thumb(const std::shared_ptr<tgl_document>& document,
        const tgl_download_callback& callback)
{
    return download_by_photo_size(document->thumb, callback);
}

int32_t tgl_transfer_manager::download_document(const std::shared_ptr<tgl_document>& document,
        const std::shared_ptr<tgl_download>& d,
        const tgl_download_callback& callback)
{
    assert(document);

    if (!document->mime_type.empty()) {
        const char* ext = tg_extension_by_mime(document->mime_type.c_str());
        if (ext) {
            d->ext = std::string(ext);
        }
    }
    begin_download(d);
    download_next_part(d, callback);
    return d->id;
}

int32_t tgl_transfer_manager::download_document(const std::shared_ptr<tgl_document>& document,
        const tgl_download_callback& callback)
{
    auto d = std::make_shared<tgl_download>(CODE_input_document_file_location, document);
    return download_document(document, d, callback);
}

int32_t tgl_transfer_manager::download_video(const std::shared_ptr<tgl_document>& document,
        const tgl_download_callback& callback)
{
    auto d = std::make_shared<tgl_download>(CODE_input_video_file_location, document);
    return download_document(document, d, callback);
}

int32_t tgl_transfer_manager::download_audio(const std::shared_ptr<tgl_document>& document,
        const tgl_download_callback& callback)
{
    auto d = std::make_shared<tgl_download>(CODE_input_audio_file_location, document);
    return download_document(document, d, callback);
}

int32_t tgl_transfer_manager::download_encr_document(const std::shared_ptr<tgl_encr_document>& document,
        const tgl_download_callback& callback)
{
    assert(document);
    auto d = std::make_shared<tgl_download>(document->size, document);
    d->key = document->key;
    d->iv = document->iv;
    if (!document->mime_type.empty()) {
        const char* extension  = tg_extension_by_mime(document->mime_type.c_str());
        if (extension) {
            d->ext = std::string(extension);
        }
    }
    download_next_part(d, callback);

    unsigned char md5[16];
    unsigned char str[64];
    memcpy(str, document->key.data(), 32);
    memcpy(str + 32, document->iv.data(), 32);
    TGLC_md5(str, 64, md5);
    assert(document->key_fingerprint == ((*(int *)md5) ^ (*(int *)(md5 + 4))));
    return d->id;
}

void tgl_transfer_manager::cancel_download(int32_t download_id)
{
    auto it = m_downloads.find(download_id);
    if (it == m_downloads.end()) {
        TGL_DEBUG("can't find download " << download_id);
        return;
    }
    it->second->cancelled = true;
    TGL_DEBUG("download " << download_id << " has been cancelled");
}

void tgl_transfer_manager::cancel_upload(int64_t message_id)
{
    auto it = m_uploads.find(message_id);
    if (it == m_uploads.end()) {
        TGL_DEBUG("can't find upload " << message_id);
        return;
    }
    it->second->cancelled = true;
    TGL_DEBUG("upload " << message_id << " has been cancelled");
}
