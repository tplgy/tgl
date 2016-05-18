#include "tgl_download_manager.h"
#include "queries.h"
#include "tg-mime-types.h"
#include "tgl-layout.h"
#include "crypto/aes.h"
#include "crypto/md5.h"
#include "mtproto-common.h"
#include "tools.h"
#include "types/tgl_message.h"

#include <fcntl.h>
#include <boost/filesystem.hpp>

class query_send_file_part: public query
{
public:
    query_send_file_part(tgl_download_manager* download_manager,
            const std::shared_ptr<send_file>& file,
            const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback)
        : query("send file part", TYPE_TO_PARAM(bool))
        , m_download_manager(download_manager)
        , m_file(file)
        , m_callback(callback)
    { }

    std::shared_ptr<query_send_file_part> shared_from_this()
    {
        return std::static_pointer_cast<query_send_file_part>(query::shared_from_this());
    }

    virtual void on_answer(void* D) override
    {
        m_download_manager->send_file_part_on_answer(shared_from_this(), D);
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << error_string);
        if (m_callback) {
            m_callback(false, nullptr);
        }
        return 0;
    }

    const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback() const
    {
        return m_callback;
    }

    const std::shared_ptr<send_file>& file() const
    {
        return m_file;
    }

private:
    tgl_download_manager* m_download_manager;
    std::shared_ptr<send_file> m_file;
    std::function<void(bool, const std::shared_ptr<tgl_message>&)> m_callback;
};

class query_set_photo: public query
{
public:
    explicit query_set_photo(const std::function<void(bool)>& callback)
        : query("set photo", TYPE_TO_PARAM(photos_photo))
        , m_callback(callback)
    { }

    std::shared_ptr<query_set_photo> shared_from_this()
    {
        return std::static_pointer_cast<query_set_photo>(query::shared_from_this());
    }

    virtual void on_answer(void* D) override
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
    explicit query_download(tgl_download_manager* download_manager,
            const std::shared_ptr<download>& download,
            const std::function<void(bool, const std::string&)>& callback)
        : query("download", TYPE_TO_PARAM(upload_file))
        , m_download_manager(download_manager)
        , m_download(download)
        , m_callback(callback)
    { }

    std::shared_ptr<query_download> shared_from_this()
    {
        return std::static_pointer_cast<query_download>(query::shared_from_this());
    }

    virtual void on_answer(void* D) override
    {
        m_download_manager->download_on_answer(shared_from_this(), D);
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        return m_download_manager->download_on_error(shared_from_this(), error_code, error_string);
    }

    const std::function<void(bool, const std::string&)>& callback() const
    {
        return m_callback;
    }

    const std::shared_ptr<download>& get_download() const
    {
        return m_download;
    }

private:
    tgl_download_manager* m_download_manager;
    std::shared_ptr<download> m_download;
    std::function<void(bool, const std::string&)> m_callback;
};

download::download(int type, std::shared_ptr<tgl_document> doc) : size(doc->size)
{
    this->type = type;
    location.set_dc(doc->dc_id);
    location.set_local_id(doc->id);
    location.set_secret(doc->access_hash);
    location.set_volume(0);
}

download::download(int type, std::shared_ptr<tgl_encr_document> doc) : size(doc->size)
{
    this->type = type;
    location.set_dc(doc->dc_id);
    location.set_local_id(doc->id);
    location.set_secret(doc->access_hash);
    location.set_volume(0);
}

tgl_download_manager::tgl_download_manager(std::string download_directory)
    : m_download_directory(download_directory)
    , cur_uploading_bytes(0)
    , cur_uploaded_bytes(0)
    , cur_downloading_bytes(0)
    , cur_downloaded_bytes(0)
{
}

bool tgl_download_manager::file_exists(const tgl_file_location &location)
{
    std::string path = get_file_path(location.access_hash());

    return boost::filesystem::exists(path);
}

bool tgl_download_manager::currently_donwloading(const tgl_file_location& location)
{
    for (auto it=m_downloads.begin(); it!= m_downloads.end(); it++) {
        if ((*it)->location.secret() == location.secret()) {
            return true;
        }
    }
    return false;
}

std::string tgl_download_manager::get_file_path(long long int secret)
{
    std::ostringstream stream;
    stream << download_directory() << "/download_" << secret;
    return stream.str();
}

int tgl_download_manager::send_file_part_on_answer(const std::shared_ptr<query_send_file_part>& q, void *D)
{
    TGL_UNUSED(D);
    send_part(q->file(), q->callback());
    return 0;
}

void tgl_download_manager::send_avatar_end (std::shared_ptr<send_file> f, const std::function<void(bool)>& callback)
{
    if (f->avatar > 0) {
        auto q = std::make_shared<query_send_msgs>(callback);
        q->out_i32 (CODE_messages_edit_chat_photo);
        q->out_i32 (f->avatar);
        q->out_i32 (CODE_input_chat_uploaded_photo);
        if (f->size < (16 << 20)) {
            q->out_i32 (CODE_input_file);
        } else {
            q->out_i32 (CODE_input_file_big);
        }
        q->out_i64 (f->id);
        q->out_i32 (f->part_num);
        q->out_string ("");
        if (f->size < (16 << 20)) {
            q->out_string ("");
        }
        q->out_i32 (CODE_input_photo_crop_auto);

        q->execute(tgl_state::instance()->working_dc());
    } else {
        auto q = std::make_shared<query_set_photo>(callback);
        q->out_i32 (CODE_photos_upload_profile_photo);
        if (f->size < (16 << 20)) {
            q->out_i32 (CODE_input_file);
        } else {
            q->out_i32 (CODE_input_file_big);
        }
        q->out_i64 (f->id);
        q->out_i32 (f->part_num);
        const char *s = f->file_name.c_str() + f->file_name.length();  // TODO do that properly
        while (s >= f->file_name && *s != '/') { s --;}
        q->out_string (s + 1);
        if (f->size < (16 << 20)) {
            q->out_string ("");
        }
        q->out_string ("profile photo");
        q->out_i32 (CODE_input_geo_point_empty);
        q->out_i32 (CODE_input_photo_crop_auto);

        q->execute(tgl_state::instance()->working_dc());
    }
}


void tgl_download_manager::send_file_unencrypted_end(std::shared_ptr<send_file> f, const std::function<void(bool, const std::shared_ptr<tgl_message>&)>&  callback) {
    std::shared_ptr<messages_send_extra> E = std::make_shared<messages_send_extra>();
    E->id = tgl_peer_id_to_random_msg_id (f->to_id);
    auto q = std::make_shared<query_send_msgs>(E, callback);
    q->out_i32 (CODE_messages_send_media);
    q->out_i32 ((f->reply ? 1 : 0));
    q->out_peer_id(f->to_id);
    if (f->reply) {
        q->out_i32 (f->reply);
    }
    if (f->flags & TGL_SEND_MSG_FLAG_DOCUMENT_PHOTO) {
        q->out_i32 (CODE_input_media_uploaded_photo);
    } else {
        if (f->thumb_id > 0) {
            q->out_i32 (CODE_input_media_uploaded_thumb_document);
        } else {
            q->out_i32 (CODE_input_media_uploaded_document);
        }
    }

    if (f->size < (16 << 20)) {
        q->out_i32 (CODE_input_file);
    } else {
        q->out_i32 (CODE_input_file_big);
    }

    q->out_i64 (f->id);
    q->out_i32 (f->part_num);
    boost::filesystem::path path = f->file_name;
    const char* file_name = path.filename().string().c_str();
    q->out_string (file_name);
    if (f->size < (16 << 20)) {
        q->out_string ("");
    }

    if (!(f->flags & TGL_SEND_MSG_FLAG_DOCUMENT_PHOTO)) {
        q->out_string (tg_mime_by_filename (f->file_name.c_str()));

        q->out_i32 (CODE_vector);
        if (f->flags & TGLDF_IMAGE) {
            if (f->flags & TGLDF_ANIMATED) {
                q->out_i32 (2);
                q->out_i32 (CODE_document_attribute_image_size);
                q->out_i32 (f->w);
                q->out_i32 (f->h);
                q->out_i32 (CODE_document_attribute_animated);
            } else {
                q->out_i32 (1);
                q->out_i32 (CODE_document_attribute_image_size);
                q->out_i32 (f->w);
                q->out_i32 (f->h);
            }
        } else if (f->flags & TGLDF_AUDIO) {
            q->out_i32 (2);
            q->out_i32 (CODE_document_attribute_audio);
            q->out_i32 (f->duration);
            q->out_i32 (CODE_document_attribute_filename);
            q->out_string (file_name);
        } else if (f->flags & TGLDF_VIDEO) {
            q->out_i32 (2);
            q->out_i32 (CODE_document_attribute_video);
            q->out_i32 (f->duration);
            q->out_i32 (f->w);
            q->out_i32 (f->h);
            q->out_i32 (CODE_document_attribute_filename);
            q->out_string (file_name);
        } else if (f->flags & TGLDF_STICKER) {
            q->out_i32 (1);
            q->out_i32 (CODE_document_attribute_sticker);
        } else {
            q->out_i32 (1);
            q->out_i32 (CODE_document_attribute_filename);
            q->out_string (file_name);
        }

        if (f->thumb_id > 0) {
            q->out_i32 (CODE_input_file);
            q->out_i64 (f->thumb_id);
            q->out_i32 (1);
            q->out_string ("thumb.jpg");
            q->out_string ("");
        }
        q->out_string (f->caption.c_str());
    } else {
        q->out_string (f->caption.c_str());
    }

    q->out_i64 (E->id.id);

    q->execute(tgl_state::instance()->working_dc());
}

void tgl_download_manager::send_file_end (std::shared_ptr<send_file> f, const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback) {
    TGL_NOTICE("send_file_end");
    cur_uploaded_bytes -= f->size;
    cur_uploading_bytes -= f->size;

    if (f->avatar) {
        send_avatar_end (f,
                [=](bool success) {
                    if(callback) {
                        callback(success, nullptr);
                    }
                });
        return;
    }
    if (!f->encr) {
        send_file_unencrypted_end (f, callback);
        return;
    }
#ifdef ENABLE_SECRET_CHAT
    send_file_encrypted_end (f, callback);
#endif
    return;
}

void tgl_download_manager::send_part(std::shared_ptr<send_file> f, const std::function<void(bool success, const std::shared_ptr<tgl_message>& M)>& callback)
{
    if (f->fd >= 0) {
        if (!f->part_num) {
            cur_uploading_bytes += f->size;
        }
        auto q = std::make_shared<query_send_file_part>(this, f, callback);
        if (f->size < (16 << 20)) {
            q->out_i32 (CODE_upload_save_file_part);
            q->out_i64 (f->id);
            q->out_i32 (f->part_num ++);
        } else {
            q->out_i32 (CODE_upload_save_big_file_part);
            q->out_i64 (f->id);
            q->out_i32 (f->part_num ++);
            q->out_i32 ((f->size + f->part_size - 1) / f->part_size);
        }
        static char buf[512 << 10];
        int x = read (f->fd, buf, f->part_size);
        assert (x > 0);
        f->offset += x;
        cur_uploaded_bytes += x;

        if (f->encr) {
            if (x & 15) {
                assert (f->offset == f->size);
                tglt_secure_random ((unsigned char*)buf + x, (-x) & 15);
                x = (x + 15) & ~15;
            }

            TGLC_aes_key aes_key;
            TGLC_aes_set_encrypt_key (f->key.data(), 256, &aes_key);
            TGLC_aes_ige_encrypt ((unsigned char *)buf, (unsigned char *)buf, x, &aes_key, f->iv.data(), 1);
            memset (&aes_key, 0, sizeof (aes_key));
        }
        q->out_string (buf, x);
        TGL_DEBUG("offset=" << f->offset << " size=" << f->size);
        if (f->offset == f->size) {
            close (f->fd);
            f->fd = -1;
        } else {
            assert (f->part_size == x);
        }

        q->execute(tgl_state::instance()->working_dc());
    } else {
        send_file_end (f, callback);
    }
}

void tgl_download_manager::send_file_thumb(std::shared_ptr<send_file> f, const void *thumb_data, int thumb_len, const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback)
{
    auto q = std::make_shared<query_send_file_part>(this, f, callback);
    f->thumb_id = lrand48 () * (1ll << 32) + lrand48 ();
    q->out_i32 (CODE_upload_save_file_part);
    q->out_i64 (f->thumb_id);
    q->out_i32 (0);
    q->out_string ((char *)thumb_data, thumb_len);

    q->execute(tgl_state::instance()->working_dc());
}


void tgl_download_manager::_tgl_do_send_photo (tgl_peer_id_t to_id, const std::string &file_name, int avatar, int w, int h, int duration,
                                const void *thumb_data, int thumb_len, const std::string& caption, unsigned long long flags,
                                const std::function<void(bool success, const std::shared_ptr<tgl_message>& M)>& callback) {
    int fd = -1;
    if (!boost::filesystem::exists(file_name)) {
        TGL_ERROR("File " << file_name << " does not exist");
        return;
    }
    long long size = boost::filesystem::file_size(file_name);
    TGL_ERROR("File " << size);
    if (size <= 0 || (fd = open (file_name.c_str(), O_RDONLY)) <= 0) {
        TGL_ERROR("File is empty");
        if (callback) {
            callback(false, nullptr);
        }
        return;
    }
    std::shared_ptr<send_file> f = std::make_shared<send_file>();
    f->fd = fd;
    f->size = size;
    f->offset = 0;
    f->part_num = 0;
    f->avatar = avatar;
    f->reply = flags >> 32;
    int tmp = ((size + 2999) / 3000);
    f->part_size = (1 << 14);
    while (f->part_size < tmp) {
        f->part_size *= 2;
    }
    f->flags = flags;

    if (f->part_size > (512 << 10)) {
        close (fd);
        TGL_ERROR("File is too big");
        if (callback) {
            callback(false, nullptr);
        }
        return;
    }

    tglt_secure_random ((unsigned char*)&f->id, 8);
    f->to_id = to_id;
    f->flags = flags;
    f->file_name = file_name;
    f->w = w;
    f->h = h;
    f->duration = duration;
    f->caption = caption;

    if (tgl_get_peer_type (f->to_id) == TGL_PEER_ENCR_CHAT) {
        f->encr = true;
        tglt_secure_random (f->iv.data(), f->iv.size());
        memcpy (f->init_iv.data(), f->iv.data(), f->iv.size());
        tglt_secure_random (f->key.data(), f->key.size());
    }

    if (!f->encr && f->flags != -1 && thumb_len > 0) {
        TGL_NOTICE("send_file_thumb");
        send_file_thumb (f, thumb_data, thumb_len, callback);
    } else {
        send_part(f, callback);
    }
}

void tgl_download_manager::set_chat_photo (tgl_peer_id_t chat_id, const std::string &file_name, const std::function<void(bool success)>& callback)
{
    assert (tgl_get_peer_type (chat_id) == TGL_PEER_CHAT);
    _tgl_do_send_photo (chat_id, file_name, tgl_get_peer_id (chat_id), 0, 0, 0, 0, 0, std::string(), TGL_SEND_MSG_FLAG_DOCUMENT_PHOTO,
            [=](bool success, const std::shared_ptr<tgl_message>&) {
                if (callback) {
                    callback(success);
                }
            });
}

void tgl_download_manager::set_profile_photo (const std::string &file_name, const std::function<void(bool success)>& callback)
{
    _tgl_do_send_photo (tgl_state::instance()->our_id(), file_name, -1, 0, 0, 0, 0, 0, std::string(), TGL_SEND_MSG_FLAG_DOCUMENT_PHOTO,
            [=](bool success, const std::shared_ptr<tgl_message>&) {
                if (callback) {
                    callback(success);
                }
            });
}

void tgl_download_manager::send_document (tgl_peer_id_t to_id, const std::string &file_name, const std::string &caption, unsigned long long flags,
        const std::function<void(bool success, const std::shared_ptr<tgl_message>& M)>& callback)
{
    TGL_DEBUG("send_document - file_name: " + file_name);
    if (flags & TGL_SEND_MSG_FLAG_DOCUMENT_AUTO) {
        const char *mime_type = tg_mime_by_filename (file_name.c_str());
        TGL_DEBUG("send_document - detected mime_type: " + std::string(mime_type));
        if (strcmp (mime_type, "image/gif") == 0) {
            flags |= TGL_SEND_MSG_FLAG_DOCUMENT_ANIMATED;
        } else if (!memcmp (mime_type, "image/", 6)) {
            flags |= TGL_SEND_MSG_FLAG_DOCUMENT_PHOTO;
        } else if (!memcmp (mime_type, "video/", 6)) {
            flags |= TGLDF_VIDEO;
        } else if (!memcmp (mime_type, "audio/", 6)) {
            flags |= TGLDF_AUDIO;
        }
    }
    _tgl_do_send_photo (to_id, file_name, 0, 100, 100, 100, 0, 0, caption, flags, callback);
}

void tgl_download_manager::end_load (std::shared_ptr<download> D, std::function<void(bool success, const std::string &filename)> callback)
{
    for (auto it=m_downloads.begin(); it != m_downloads.end(); it++) {
        if (*it == D) {
            m_downloads.erase(it);
            break;
        }
    }

    cur_downloading_bytes -= D->size;
    cur_downloaded_bytes -= D->size;

    if (D->fd >= 0) {
        close (D->fd);
    }

    if (callback) {
        callback(true, D->name);
    }
}

int tgl_download_manager::download_on_answer(const std::shared_ptr<query_download>& q, void *DD)
{
    struct tl_ds_upload_file *DS_UF = (struct tl_ds_upload_file *)DD;

    const std::shared_ptr<download>& D = q->get_download();
    if (D->fd == -1) {
        D->fd = open (D->name.c_str(), O_CREAT | O_WRONLY, 0640);
        if (D->fd < 0) {
            TGL_ERROR("Can not open file for writing: %m");
            if (q->callback()) {
                (q->callback())(false, std::string());
            }

            return 0;
        }
    }

    int len = DS_UF->bytes->len;
    cur_downloaded_bytes += len;

    if (!D->iv.empty()) {
        assert (!(len & 15));
        void *ptr = DS_UF->bytes->data;

        TGLC_aes_key aes_key;
        TGLC_aes_set_decrypt_key (D->key.data(), 256, &aes_key);
        TGLC_aes_ige_encrypt ((unsigned char*)ptr, (unsigned char*)ptr, len, &aes_key, D->iv.data(), 0);
        memset ((unsigned char*)&aes_key, 0, sizeof (aes_key));
        if (len > D->size - D->offset) {
            len = D->size - D->offset;
        }
        auto result = write (D->fd, ptr, len);
        TGL_ASSERT_UNUSED(result, result == len);
    } else {
        auto result = write (D->fd, DS_UF->bytes->data, len);
        TGL_ASSERT_UNUSED(result, result == len);
    }

    D->offset += len;
    D->refcnt --;
    if (D->offset < D->size) {
        load_next_part(D, q->callback());
        return 0;
    } else {
        if (!D->refcnt) {
            end_load(D, q->callback());
        }
        return 0;
    }
}

int tgl_download_manager::download_on_error(const std::shared_ptr<query_download>& q, int error_code, const std::string &error)
{
    TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << std::string(error));

    const std::shared_ptr<download>& D = q->get_download();
    if (D->fd >= 0) {
        close (D->fd);
    }

    if (q->callback()) {
        (q->callback())(false, D->name);
    }

    return 0;
}

void tgl_download_manager::begin_download(std::shared_ptr<download> new_download)
{
    m_downloads.push_back(new_download);
}

void tgl_download_manager::load_next_part (std::shared_ptr<download> D, std::function<void(bool, const std::string &)> callback)
{
    if (!D->offset) {
        std::string path = get_file_path(D->location.access_hash());

        if (!D->ext.empty()) {
            path += std::string(".") + D->ext;
        }

        D->name = path;
        if (boost::filesystem::exists(path)) {
            D->offset = boost::filesystem::file_size(path);
            if (D->offset >= D->size) {
                cur_downloading_bytes += D->size;
                cur_downloaded_bytes += D->offset;
                TGL_NOTICE("Already downloaded");
                end_load(D, callback);
                return;
            }
        }

        cur_downloading_bytes += D->size;
        cur_downloaded_bytes += D->offset;
    }
    D->refcnt ++;
    auto q = std::make_shared<query_download>(this, D, callback);
    q->out_i32 (CODE_upload_get_file);
    if (D->location.local_id()) {
        q->out_i32 (CODE_input_file_location);
        q->out_i64 (D->location.volume());
        q->out_i32 (D->location.local_id());
        q->out_i64 (D->location.secret());
    } else {
        if (!D->iv.empty()) {
            q->out_i32 (CODE_input_encrypted_file_location);
        } else {
            q->out_i32 (D->type);
        }
        q->out_i64 (D->location.document_id());
        q->out_i64 (D->location.access_hash());
    }
    q->out_i32 (D->offset);
    q->out_i32 (D->size ? (1 << 14) : (1 << 19));

    q->execute(tgl_state::instance()->dc_at(D->location.dc()));
}

void tgl_download_manager::download_photo_size (const std::shared_ptr<tgl_photo_size>& P, std::function<void(bool success, const std::string &filename)> callback)
{
    if (!P->loc.dc()) {
        TGL_WARNING("Bad video thumb");
        if (callback) {
            callback(false, std::string());
        }
        return;
    }

    assert (P);
    std::shared_ptr<download> D = std::make_shared<download>(P->size, P->loc);
    load_next_part (D, callback);
}

void tgl_download_manager::download_file_location(const tgl_file_location& file_location, std::function<void(bool success, const std::string &filename)> callback)
{
    if (!file_location.dc()) {
        TGL_ERROR("Bad file location");
        if (callback) {
            callback(false, std::string());
        }
        return;
    }

    std::shared_ptr<download> D = std::make_shared<download>(0, file_location);
    load_next_part(D, callback);
}

void tgl_download_manager::download_photo(struct tgl_photo *photo, std::function<void(bool success, const std::string &filename)> callback)
{
    if (!photo->sizes.size()) {
        TGL_ERROR("Bad photo (no photo sizes");
        if (callback) {
            callback(false, std::string());
        }
        return;
    }
    int max = -1;
    int maxi = 0;
    int i;
    for (i = 0; i < static_cast<int>(photo->sizes.size()); i++) {
        if (photo->sizes[i]->w + photo->sizes[i]->h > max) {
            max = photo->sizes[i]->w + photo->sizes[i]->h;
            maxi = i;
        }
    }
    download_photo_size(photo->sizes[maxi], callback);
}

void tgl_download_manager::download_document_thumb (struct tgl_document *video, std::function<void(bool success, const std::string &filename)> callback)
{
    download_photo_size(video->thumb, callback);
}

void tgl_download_manager::_tgl_do_load_document(std::shared_ptr<tgl_document> doc, std::shared_ptr<download> D, std::function<void(bool success, const std::string &filename)> callback)
{
    assert(doc);

    if (!doc->mime_type.empty()) {
        const char *ext = tg_extension_by_mime(doc->mime_type.c_str());
        if (ext) {
            D->ext = std::string(ext);
        }
    }
    begin_download(D);
    load_next_part(D, callback);
}

void tgl_download_manager::download_document(std::shared_ptr<tgl_document> document, std::function<void(bool success, const std::string &filename)> callback)
{
    std::shared_ptr<download> D = std::make_shared<download>(CODE_input_document_file_location, document);

    _tgl_do_load_document (document, D, callback);
}

void tgl_download_manager::download_video (std::shared_ptr<tgl_document> V, std::function<void(bool success, const std::string &filename)> callback)
{
    std::shared_ptr<download> D = std::make_shared<download>(CODE_input_video_file_location, V);

    _tgl_do_load_document (V, D, callback);
}

void tgl_download_manager::download_audio(std::shared_ptr<tgl_document> V, std::function<void(bool success, const std::string &filename)> callback)
{
    std::shared_ptr<download> D = std::make_shared<download>(CODE_input_audio_file_location, V);

    _tgl_do_load_document(V, D, callback);
}

void tgl_download_manager::download_encr_document(std::shared_ptr<tgl_encr_document> V, std::function<void(bool success, const std::string &filename)> callback)
{
    assert (V);
    std::shared_ptr<download> D = std::make_shared<download>(V->size, V);
    D->key = V->key;
    D->iv = V->iv;
    if (!V->mime_type.empty()) {
        const char *r = tg_extension_by_mime (V->mime_type.c_str());
        if (r) {
            D->ext = std::string(r);
        }
    }
    load_next_part(D, callback);

    unsigned char md5[16];
    unsigned char str[64];
    memcpy (str, V->key.data(), 32);
    memcpy (str + 32, V->iv.data(), 32);
    TGLC_md5 (str, 64, md5);
    assert (V->key_fingerprint == ((*(int *)md5) ^ (*(int *)(md5 + 4))));
}
