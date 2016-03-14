#ifndef TGL_DOWNLOAD_MANAGER_H
#define TGL_DOWNLOAD_MANAGER_H

#include <vector>
#include <string>
#include "types/tgl_file_location.h"
#include "types/tgl_peer_id.h"
#include "types/query_methods.h"

struct file_download {
    std::string path;
    tgl_file_location location;
};

struct tgl_document;
struct  tgl_encr_document;
struct download {
    download(int size, tgl_file_location location)
        : location(location), offset(0), size(size), fd(-1), iv(NULL), key(NULL), type(0), refcnt(0)
    {
    }

    download(int type, tgl_document*);
    download(int type, tgl_encr_document*);

    tgl_file_location location;
    int offset;
    int size;
    int fd;
    std::string name;
    std::string ext;
    unsigned char *iv;
    unsigned char *key;
    int type;
    int refcnt;
};

class tgl_download_manager
{
public:
    tgl_download_manager(std::string download_directory);
    bool download_file(file_download new_download);
    std::string download_directory() { return m_download_directory; }

    int download_error(struct query *q, int error_code, int error_len, const char *error);

    void download_encr_document(struct tgl_encr_document *V, void (*callback)(void *callback_extra,
            int success, const char *filename), void *callback_extra);
    void download_audio(struct tgl_document *V, void (*callback)(void *callback_extra, int success, const char *filename),
            void *callback_extra);
    void download_video(struct tgl_document *V, void (*callback)(void *callback_extra, int success, const char *filename),
            void *callback_extra);
    void download_document_thumb(struct tgl_document *video, void (*callback)(void *callback_extra, int success, const char *filename),
            void *callback_extra);
    void download_photo(struct tgl_photo *photo, void (*callback)(void *callback_extra, int success, const char *filename), void *callback_extra);

    void send_document(tgl_peer_id to_id, const char *file_name, const char *caption, unsigned long long flags,
            void (*callback)(void *callback_extra, int success, struct tgl_message *M), void *callback_extra);
    // sets self profile photo
    // server will cut central square from this photo
    void set_profile_photo(const char *file_name, void (*callback)(void *callback_extra, int success), void *callback_extra);
    void set_chat_photo(tgl_peer_id chat_id, const char *file_name, void (*callback)(void *callback_extra, int success), void *callback_extra);

    void download_photo_size(struct tgl_photo_size *P, void (*callback)(void *callback_extra, int success, const char *filename),
            void *callback_extra);

    void download_file_location(struct tgl_file_location *P, void (*callback)(void *callback_extra, int success, const char *filename),
            void *callback_extra);

    void download_document(struct tgl_document *V, void (*callback)(void *callback_extra, int success, const char *filename),
            void *callback_extra);

    void tgl_do_reply_document(long long int reply_id, tgl_peer_id peer_id, const char *file_name, const char *caption, unsigned long long flags,
            void (*callback)(void *callback_extra, int success, struct tgl_message *M), void *callback_extra);

    // Callbacks
    int download_on_answer(struct query *q, void *DD);
    int download_on_error(struct query *q, int error_code, int error_len, const char *error);
    int send_file_part_on_answer(struct query *q, void *D);
    int send_file_part_on_error(struct query *q, int error_code, int error_len, const char *error);
    int set_photo_on_answer(struct query *q, void *D);
private:
    void send_avatar_end(struct send_file *f, void *callback, void *callback_extra);
    void send_file_end(struct send_file *f, void *callback, void *callback_extra);
    void send_file_thumb(struct send_file *f, const void *thumb_data, int thumb_len, void *callback, void *callback_extra);

    void send_part(struct send_file *f, void *callback, void *callback_extra);

    void _tgl_do_send_photo(tgl_peer_id to_id, const char *file_name, int avatar, int w, int h, int duration,
                                    const void *thumb_data, int thumb_len, const char *caption, unsigned long long flags,
                                    void (*callback)(void *callback_extra, int success, struct tgl_message *M), void *callback_extra);
    void _tgl_do_load_document(struct tgl_document *V, struct download *D, void (*callback)(void *callback_extra,
                                    int success, const char *filename), void *callback_extra);
    void load_next_part(struct download *D, void *callback, void *callback_extra);
    void end_load(struct download *D, void *callback, void *callback_extra);

    std::vector<file_download> m_queued_downloads;

    std::string m_download_directory;

    query_methods m_send_file_part_methods;
    query_methods m_download_methods;
    query_methods m_set_photo_methods;

    long long cur_uploading_bytes;
    long long cur_uploaded_bytes;
    long long cur_downloading_bytes;
    long long cur_downloaded_bytes;
};

#endif // TGL_DOWNLOAD_MANAGER_H
