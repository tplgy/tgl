#include "tgl_download_manager.h"
#include "queries.h"
#include "tg-mime-types.h"
#include "tgl-layout.h"
#include "crypto/aes.h"
#include "crypto/md5.h"
#include "mtproto-common.h"
#include "tools.h"

#include <fcntl.h>
#include <boost/filesystem.hpp>

extern struct query_methods send_msgs_methods;

download::download(int type, tgl_document *doc) : size(doc->size)
{
    this->type = type;
    location.set_dc(doc->dc_id);
    location.set_local_id(doc->id);
    location.set_secret(doc->access_hash);
    location.set_volume(0);
}

download::download(int type, tgl_encr_document *doc) : size(doc->size)
{
    this->type = type;
    location.set_dc(doc->dc_id);
    location.set_local_id(doc->id);
    location.set_secret(doc->access_hash);
    location.set_volume(0);
}

tgl_download_manager::tgl_download_manager(std::string download_directory)
        : m_download_directory(download_directory)
{
    m_send_file_part_methods = {
        .on_answer = std::bind(&tgl_download_manager::send_file_part_on_answer, this, std::placeholders::_1, std::placeholders::_2),
        .on_error = std::bind(&tgl_download_manager::send_file_part_on_error, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3),
        .on_timeout = NULL,
        .type = (struct paramed_type) {.type = &tl_type_bool, .params=0},
        .name = "send file part",
        .timeout = 0
    };

    m_download_methods = {
        .on_answer = std::bind(&tgl_download_manager::download_on_answer, this, std::placeholders::_1, std::placeholders::_2),
        .on_error = std::bind(&tgl_download_manager::download_on_error, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3),
        .on_timeout = NULL,
        .type = TYPE_TO_PARAM(upload_file),
        .name = "download",
        .timeout = 0
    };

    m_set_photo_methods = {
        .on_answer = std::bind(&tgl_download_manager::set_photo_on_answer, this, std::placeholders::_1, std::placeholders::_2),
        .on_error = std::bind(&tgl_download_manager::download_error, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3),
        .on_timeout = NULL,
        .type = TYPE_TO_PARAM(photos_photo),
        .name = "set photo",
        .timeout = 0
    };
}

bool tgl_download_manager::file_exists(const tgl_file_location &location)
{
    std::string path = get_file_path(location.access_hash());

    return boost::filesystem::exists(path);
}

std::string tgl_download_manager::get_file_path(long long int secret)
{
    return download_directory() + "/download_" + std::to_string(secret);
}

int tgl_download_manager::download_error (std::shared_ptr<query> q, int error_code, const std::string &error)
{
    TGL_ERROR("Download error for query " << q->msg_id << " " << error_code << " " << std::string(error));
    return 0;
}

int tgl_download_manager::send_file_part_on_answer (std::shared_ptr<query> q, void *D)
{
    TGL_UNUSED(D);
    send_part(std::static_pointer_cast<send_file>(q->extra), (void*)q->callback, q->callback_extra);
    return 0;
}

int tgl_download_manager::set_photo_on_answer (std::shared_ptr<query> q, void *D)
{
    TGL_UNUSED(D);
    if (q->callback) {
        ((void (*)(std::shared_ptr<void>, int))q->callback)(q->callback_extra, 1);
    }
    return 0;
}

int tgl_download_manager::send_file_part_on_error (std::shared_ptr<query> q, int error_code, const std::string &error)
{
    TGL_ERROR("RPC_CALL_FAIL " << error_code << error);

    std::shared_ptr<send_file> f = std::static_pointer_cast<send_file>(q->extra);
    if (!f->avatar) {
        if (q->callback) {
            ((void (*)(std::shared_ptr<void>, int, struct tgl_message *))q->callback) (q->callback_extra, 0, 0);
        }
    } else {
        if (q->callback) {
            ((void (*)(std::shared_ptr<void>, int))q->callback) (q->callback_extra, 0);
        }
    }
    return 0;
}

void tgl_download_manager::send_avatar_end (std::shared_ptr<send_file> f, void *callback, std::shared_ptr<void> callback_extra)
{
    if (f->avatar > 0) {
        out_int (CODE_messages_edit_chat_photo);
        out_int (f->avatar);
        out_int (CODE_input_chat_uploaded_photo);
        if (f->size < (16 << 20)) {
            out_int (CODE_input_file);
        } else {
            out_int (CODE_input_file_big);
        }
        out_long (f->id);
        out_int (f->part_num);
        out_string ("");
        if (f->size < (16 << 20)) {
            out_string ("");
        }
        out_int (CODE_input_photo_crop_auto);
        tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer,
                &send_msgs_methods, NULL, callback, callback_extra);
    } else {
        out_int (CODE_photos_upload_profile_photo);
        if (f->size < (16 << 20)) {
            out_int (CODE_input_file);
        } else {
            out_int (CODE_input_file_big);
        }
        out_long (f->id);
        out_int (f->part_num);
        const char *s = f->file_name.c_str() + f->file_name.length();  // TODO do that properly
        while (s >= f->file_name && *s != '/') { s --;}
        out_string (s + 1);
        if (f->size < (16 << 20)) {
            out_string ("");
        }
        out_string ("profile photo");
        out_int (CODE_input_geo_point_empty);
        out_int (CODE_input_photo_crop_auto);
        tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer,
                &m_set_photo_methods, 0, (void*)callback, callback_extra);
    }
}


void tgl_download_manager::send_file_unencrypted_end (std::shared_ptr<send_file> f, void *callback, std::shared_ptr<void> callback_extra) {
    out_int (CODE_messages_send_media);
    out_int ((f->reply ? 1 : 0));
    out_peer_id(f->to_id);
    if (f->reply) {
        out_int (f->reply);
    }
    if (f->flags & TGL_SEND_MSG_FLAG_DOCUMENT_PHOTO) {
        out_int (CODE_input_media_uploaded_photo);
    } else {
        if (f->thumb_id > 0) {
            out_int (CODE_input_media_uploaded_thumb_document);
        } else {
            out_int (CODE_input_media_uploaded_document);
        }
    }

    if (f->size < (16 << 20)) {
        out_int (CODE_input_file);
    } else {
        out_int (CODE_input_file_big);
    }

    out_long (f->id);
    out_int (f->part_num);
    const char *s = f->file_name.c_str() + f->file_name.length();
    while (s >= f->file_name && *s != '/') { s --;}
    out_string (s + 1);
    if (f->size < (16 << 20)) {
        out_string ("");
    }

    if (!(f->flags & TGL_SEND_MSG_FLAG_DOCUMENT_PHOTO)) {
        out_string (tg_mime_by_filename (f->file_name.c_str()));

        out_int (CODE_vector);
        if (f->flags & TGLDF_IMAGE) {
            if (f->flags & TGLDF_ANIMATED) {
                out_int (2);
                out_int (CODE_document_attribute_image_size);
                out_int (f->w);
                out_int (f->h);
                out_int (CODE_document_attribute_animated);
            } else {
                out_int (1);
                out_int (CODE_document_attribute_image_size);
                out_int (f->w);
                out_int (f->h);
            }
        } else if (f->flags & TGLDF_AUDIO) {
            out_int (2);
            out_int (CODE_document_attribute_audio);
            out_int (f->duration);
            out_int (CODE_document_attribute_filename);
            out_string (s + 1);
        } else if (f->flags & TGLDF_VIDEO) {
            out_int (2);
            out_int (CODE_document_attribute_video);
            out_int (f->duration);
            out_int (f->w);
            out_int (f->h);
            out_int (CODE_document_attribute_filename);
            out_string (s + 1);
        } else if (f->flags & TGLDF_STICKER) {
            out_int (1);
            out_int (CODE_document_attribute_sticker);
        } else {
            out_int (1);
            out_int (CODE_document_attribute_filename);
            out_string (s + 1);
        }

        if (f->thumb_id > 0) {
            out_int (CODE_input_file);
            out_long (f->thumb_id);
            out_int (1);
            out_string ("thumb.jpg");
            out_string ("");
        }
    } else {
        out_string (f->caption.c_str());
    }

    std::shared_ptr<messages_send_extra> E = std::make_shared<messages_send_extra>();
    E->id = tgl_peer_id_to_random_msg_id (f->to_id);
    out_long (E->id.id);

    tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_msgs_methods, E, callback, callback_extra);
}

void tgl_download_manager::send_file_end (std::shared_ptr<send_file> f, void *callback, std::shared_ptr<void> callback_extra) {
    TGL_NOTICE("send_file_end");
    cur_uploaded_bytes -= f->size;
    cur_uploading_bytes -= f->size;
    clear_packet ();

    if (f->avatar) {
        send_avatar_end (f, callback, callback_extra);
        return;
    }
    if (!f->encr) {
        send_file_unencrypted_end (f, callback, callback_extra);
        return;
    }
#ifdef ENABLE_SECRET_CHAT
    send_file_encrypted_end (f, callback, callback_extra);
#endif
    return;
}

void tgl_download_manager::send_part(std::shared_ptr<send_file> f, void *callback, std::shared_ptr<void> callback_extra)
{
    if (f->fd >= 0) {
        if (!f->part_num) {
            cur_uploading_bytes += f->size;
        }
        clear_packet ();
        if (f->size < (16 << 20)) {
            out_int (CODE_upload_save_file_part);
            out_long (f->id);
            out_int (f->part_num ++);
        } else {
            out_int (CODE_upload_save_big_file_part);
            out_long (f->id);
            out_int (f->part_num ++);
            out_int ((f->size + f->part_size - 1) / f->part_size);
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
            TGLC_aes_set_encrypt_key (f->key, 256, &aes_key);
            TGLC_aes_ige_encrypt ((unsigned char *)buf, (unsigned char *)buf, x, &aes_key, f->iv, 1);
            memset (&aes_key, 0, sizeof (aes_key));
        }
        out_cstring (buf, x);
        TGL_DEBUG("offset=" << f->offset << " size=" << f->size);
        if (f->offset == f->size) {
            close (f->fd);
            f->fd = -1;
        } else {
            assert (f->part_size == x);
        }
        tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &m_send_file_part_methods, f, callback, callback_extra);
    } else {
        send_file_end (f, callback, callback_extra);
    }
}

void tgl_download_manager::send_file_thumb (std::shared_ptr<send_file> f, const void *thumb_data, int thumb_len, void *callback, std::shared_ptr<void> callback_extra)
{
    clear_packet ();
    f->thumb_id = lrand48 () * (1ll << 32) + lrand48 ();
    out_int (CODE_upload_save_file_part);
    out_long (f->thumb_id);
    out_int (0);
    out_cstring ((char *)thumb_data, thumb_len);
    tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &m_send_file_part_methods, f, callback, callback_extra);
}


void tgl_download_manager::_tgl_do_send_photo (tgl_peer_id_t to_id, const std::string &file_name, int avatar, int w, int h, int duration,
                                const void *thumb_data, int thumb_len, const std::string &caption, unsigned long long flags,
                                void (*callback)(std::shared_ptr<void> callback_extra, bool success, struct tgl_message *M), std::shared_ptr<void> callback_extra) {
    int fd = -1;
    if (!boost::filesystem::exists(file_name)) {
        TGL_ERROR("File " << file_name << " does not exist");
        return;
    }
    long long size = boost::filesystem::file_size(file_name);
    TGL_ERROR("File " << size);
    if (size <= 0 || (fd = open (file_name.c_str(), O_RDONLY)) <= 0) {
        TGL_ERROR("File is empty");
        if (!avatar) {
            if (callback) {
                callback (callback_extra, 0, 0);
            }
        } else {
            if (callback) {
                ((void (*)(std::shared_ptr<void>, int))callback) (callback_extra, 0);
            }
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
        if (!avatar) {
            if (callback) {
                callback (callback_extra, 0, 0);
            }
        } else {
            if (callback) {
                ((void (*)(std::shared_ptr<void>, int))callback) (callback_extra, 0);
            }
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
        f->encr = 1;
        f->iv = (unsigned char *)malloc (32);
        tglt_secure_random (f->iv, 32);
        f->init_iv = (unsigned char *)malloc (32);
        memcpy (f->init_iv, f->iv, 32);
        f->key = (unsigned char *)malloc (32);
        tglt_secure_random (f->key, 32);
    }

    if (!f->encr && f->flags != -1 && thumb_len > 0) {
        TGL_NOTICE("send_file_thumb");
        send_file_thumb (f, thumb_data, thumb_len, (void*)callback, callback_extra);
    } else {
        send_part (f, (void*)callback, callback_extra);
    }
}

void tgl_download_manager::set_chat_photo (tgl_peer_id_t chat_id, const std::string &file_name, void (*callback)(std::shared_ptr<void> callback_extra, bool success),
        std::shared_ptr<void> callback_extra)
{
    assert (tgl_get_peer_type (chat_id) == TGL_PEER_CHAT);
    _tgl_do_send_photo (chat_id, file_name, tgl_get_peer_id (chat_id), 0, 0, 0, 0, 0, NULL, TGL_SEND_MSG_FLAG_DOCUMENT_PHOTO,
                        (void (*)(std::shared_ptr<void>, bool , struct tgl_message *))callback, callback_extra);
}

void tgl_download_manager::set_profile_photo (const std::string &file_name, void (*callback)(std::shared_ptr<void> callback_extra, bool success), std::shared_ptr<void> callback_extra)
{
    _tgl_do_send_photo (tgl_state::instance()->our_id(), file_name, -1, 0, 0, 0, 0, 0, NULL, TGL_SEND_MSG_FLAG_DOCUMENT_PHOTO,
                        (void (*)(std::shared_ptr<void>, bool , struct tgl_message *))callback, callback_extra);
}


void tgl_download_manager::send_document (tgl_peer_id_t to_id, const std::string &file_name, const std::string &caption, unsigned long long flags,
        void (*callback)(std::shared_ptr<void> callback_extra, bool success, struct tgl_message *M), std::shared_ptr<void> callback_extra)
{
    if (flags & TGL_SEND_MSG_FLAG_DOCUMENT_AUTO) {
        const char *mime_type = tg_mime_by_filename (file_name.c_str());
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
    _tgl_do_send_photo (to_id, file_name, 0, 100, 100, 100, 0, 0, caption, flags, callback, callback_extra);
}

void tgl_download_manager::end_load (std::shared_ptr<download> D, void *callback, std::shared_ptr<void> callback_extra)
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
        ((void (*)(std::shared_ptr<void>, bool, const std::string&))callback) (callback_extra, true, D->name);
    }

    if (D->iv) {
        free(D->iv);
    }
}

int tgl_download_manager::download_on_answer (std::shared_ptr<query> q, void *DD)
{
    struct tl_ds_upload_file *DS_UF = (struct tl_ds_upload_file *)DD;

    std::shared_ptr<download> D = std::static_pointer_cast<download>(q->extra);
    if (D->fd == -1) {
        D->fd = open (D->name.c_str(), O_CREAT | O_WRONLY, 0640);
        if (D->fd < 0) {
            TGL_ERROR("Can not open file for writing: %m");
            if (q->callback) {
                ((void (*)(std::shared_ptr<void>, bool, const std::string&))q->callback) (q->callback_extra, false, NULL);
            }

            if (D->iv) {
                free(D->iv);
            }
            return 0;
        }
    }

    int len = DS_UF->bytes->len;
    cur_downloaded_bytes += len;

    if (D->iv) {
        assert (!(len & 15));
        void *ptr = DS_UF->bytes->data;

        TGLC_aes_key aes_key;
        TGLC_aes_set_decrypt_key (D->key, 256, &aes_key);
        TGLC_aes_ige_encrypt ((unsigned char*)ptr, (unsigned char*)ptr, len, &aes_key, D->iv, 0);
        memset ((unsigned char*)&aes_key, 0, sizeof (aes_key));
        if (len > D->size - D->offset) {
            len = D->size - D->offset;
        }
        assert (write (D->fd, ptr, len) == len);
    } else {
        assert (write (D->fd, DS_UF->bytes->data, len) == len);
    }

    D->offset += len;
    D->refcnt --;
    if (D->offset < D->size) {
        load_next_part (D, q->callback, q->callback_extra);
        return 0;
    } else {
        if (!D->refcnt) {
            end_load (D, q->callback, q->callback_extra);
        }
        return 0;
    }
}

int tgl_download_manager::download_on_error (std::shared_ptr<query> q, int error_code, const std::string &error)
{
    TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << std::string(error));

    std::shared_ptr<download> D = std::static_pointer_cast<download>(q->extra);
    if (D->fd >= 0) {
        close (D->fd);
    }

    if (q->callback) {
        ((void (*)(std::shared_ptr<void>, bool, const std::string&))q->callback)(q->callback_extra, false, D->name);
    }

    if (D->iv) {
        free (D->iv);
    }
    return 0;
}

void tgl_download_manager::begin_download(std::shared_ptr<download> new_download)
{
    m_downloads.push_back(new_download);
}

void tgl_download_manager::load_next_part (std::shared_ptr<download> D, void *callback, std::shared_ptr<void> callback_extra)
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
                end_load (D, callback, callback_extra);
                return;
            }
        }

        cur_downloading_bytes += D->size;
        cur_downloaded_bytes += D->offset;
    }
    D->refcnt ++;
    clear_packet ();
    out_int (CODE_upload_get_file);
    if (D->location.local_id()) {
        out_int (CODE_input_file_location);
        out_long (D->location.volume());
        out_int (D->location.local_id());
        out_long (D->location.secret());
    } else {
        if (D->iv) {
            out_int (CODE_input_encrypted_file_location);
        } else {
            out_int (D->type);
        }
        out_long (D->location.document_id());
        out_long (D->location.access_hash());
    }
    out_int (D->offset);
    out_int (D->size ? (1 << 14) : (1 << 19));

    tglq_send_query (tgl_state::instance()->DC_list[D->location.dc()], packet_ptr - packet_buffer, packet_buffer, &m_download_methods, D, callback, callback_extra);
}

void tgl_download_manager::download_photo_size (struct tgl_photo_size *P, void (*callback)(std::shared_ptr<void> callback_extra, bool success, const std::string &filename),
        std::shared_ptr<void> callback_extra)
{
    if (!P->loc.dc()) {
        TGL_WARNING("Bad video thumb");
        if (callback) {
            callback (callback_extra, 0, 0);
        }
        return;
    }

    assert (P);
    std::shared_ptr<download> D = std::make_shared<download>(P->size, P->loc);
    load_next_part (D, (void*)callback, callback_extra);
}

void tgl_download_manager::download_file_location (struct tgl_file_location file_location, void (*callback)(std::shared_ptr<void> callback_extra, bool success, const std::string &filename),
        std::shared_ptr<void> callback_extra)
{
    if (!file_location.dc()) {
        TGL_ERROR("Bad file location");
        if (callback) {
            callback (callback_extra, false, std::string());
        }
        return;
    }

    std::shared_ptr<download> D = std::make_shared<download>(0, file_location);
    load_next_part (D, (void*)callback, callback_extra);
}

void tgl_download_manager::download_photo(struct tgl_photo *photo, void (*callback)(std::shared_ptr<void> callback_extra, bool success, const std::string &filename), std::shared_ptr<void> callback_extra)
{
    if (!photo->sizes_num) {
        TGL_ERROR("Bad photo (no photo sizes");
        if (callback) {
            callback (callback_extra, 0, 0);
        }
        return;
    }
    int max = -1;
    int maxi = 0;
    int i;
    for (i = 0; i < photo->sizes_num; i++) {
        if (photo->sizes[i].w + photo->sizes[i].h > max) {
            max = photo->sizes[i].w + photo->sizes[i].h;
            maxi = i;
        }
    }
    download_photo_size(&photo->sizes[maxi], callback, callback_extra);
}

void tgl_download_manager::download_document_thumb (struct tgl_document *video, void (*callback)(std::shared_ptr<void> callback_extra, bool success, const std::string &filename), std::shared_ptr<void> callback_extra)
{
    download_photo_size(&video->thumb, callback, callback_extra);
}

void tgl_download_manager::_tgl_do_load_document (struct tgl_document *V, std::shared_ptr<download> D, void (*callback)(std::shared_ptr<void> callback_extra, bool success, const std::string &filename), std::shared_ptr<void> callback_extra)
{
    assert (V);

    if (V->mime_type) {
        const char *r = tg_extension_by_mime (V->mime_type);
        if (r) {
            D->ext = std::string(r);
        }
    }
    load_next_part(D, (void*)callback, callback_extra);
}

void tgl_download_manager::download_document (struct tgl_document *V, void (*callback)(std::shared_ptr<void> callback_extra, bool success, const std::string &filename),
        std::shared_ptr<void> callback_extra)
{

    std::shared_ptr<download> D = std::make_shared<download>(CODE_input_document_file_location, V);

    _tgl_do_load_document (V, D, callback, callback_extra);
}

void tgl_download_manager::download_video (struct tgl_document *V, void (*callback)(std::shared_ptr<void> callback_extra, bool success, const std::string &filename),
        std::shared_ptr<void> callback_extra)
{
    std::shared_ptr<download> D = std::make_shared<download>(CODE_input_video_file_location, V);

    _tgl_do_load_document (V, D, callback, callback_extra);
}

void tgl_download_manager::download_audio (struct tgl_document *V, void (*callback)(std::shared_ptr<void> callback_extra, bool success, const std::string &filename),
        std::shared_ptr<void> callback_extra)
{
    std::shared_ptr<download> D = std::make_shared<download>(CODE_input_audio_file_location, V);

    _tgl_do_load_document (V, D, callback, callback_extra);
}

void tgl_download_manager::download_encr_document (struct tgl_encr_document *V, void (*callback)(std::shared_ptr<void> callback_extra, bool success, const std::string &filename), std::shared_ptr<void> callback_extra)
{
    assert (V);
    std::shared_ptr<download> D = std::make_shared<download>(V->size, V);
    D->key = V->key;
    D->iv = (unsigned char *)malloc (32);
    memcpy (D->iv, V->iv, 32);
    if (V->mime_type) {
        const char *r = tg_extension_by_mime (V->mime_type);
        if (r) {
            D->ext = std::string(r);
        }
    }
    load_next_part(D, (void*)callback, callback_extra);

    unsigned char md5[16];
    unsigned char str[64];
    memcpy (str, V->key, 32);
    memcpy (str + 32, V->iv, 32);
    TGLC_md5 (str, 64, md5);
    assert (V->key_fingerprint == ((*(int *)md5) ^ (*(int *)(md5 + 4))));
}
